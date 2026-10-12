package service_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"golang.org/x/crypto/bcrypt"

	"restaurant-api/db/sqlc"
	"restaurant-api/internal/repository"
	"restaurant-api/internal/service"
)

type stubAdminReader struct {
	admin             sqlc.Admin
	err               error
	restaurantRoles   []sqlc.ListAdminRestaurantRolesRow
	restaurantRoleErr error
}

func (s stubAdminReader) GetByLogin(ctx context.Context, login string) (sqlc.Admin, error) {
	return s.admin, s.err
}

func (s stubAdminReader) GetByID(ctx context.Context, id int64) (sqlc.Admin, error) {
	return s.admin, s.err
}

func (s stubAdminReader) ListRestaurantRoles(ctx context.Context, adminID int64) ([]sqlc.ListAdminRestaurantRolesRow, error) {
	return s.restaurantRoles, s.restaurantRoleErr
}

type stubTokenIssuer struct {
	token     string
	expiresIn int64
	err       error
}

func (s stubTokenIssuer) IssueAccessToken(adminID int64) (string, int64, error) {
	return s.token, s.expiresIn, s.err
}

type stubRefreshIssuer struct {
	raw       string
	hash      string
	expiresAt time.Time
	expiresIn int64
	err       error
	issueN    int
}

func (s *stubRefreshIssuer) Issue() (string, string, time.Time, int64, error) {
	s.issueN++
	if s.err != nil {
		return "", "", time.Time{}, 0, s.err
	}
	// Produce distinct tokens per issue for rotation tests.
	raw := s.raw
	hash := s.hash
	if s.issueN > 1 {
		raw = s.raw + "-rotated"
		hash = s.hash + "-rotated"
	}
	return raw, hash, s.expiresAt, s.expiresIn, nil
}

func (s *stubRefreshIssuer) Hash(rawToken string) string {
	if rawToken == s.raw {
		return s.hash
	}
	if rawToken == s.raw+"-rotated" {
		return s.hash + "-rotated"
	}
	return "unknown-hash"
}

type memoryRefreshStore struct {
	byHash map[string]sqlc.AdminRefreshSession
	nextID int64
}

func newMemoryRefreshStore() *memoryRefreshStore {
	return &memoryRefreshStore{byHash: map[string]sqlc.AdminRefreshSession{}, nextID: 1}
}

func (m *memoryRefreshStore) Create(ctx context.Context, adminID int64, tokenHash string, expiresAt time.Time) (sqlc.AdminRefreshSession, error) {
	session := sqlc.AdminRefreshSession{
		ID:        m.nextID,
		AdminID:   adminID,
		TokenHash: tokenHash,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt.UTC(), Valid: true},
	}
	m.nextID++
	m.byHash[tokenHash] = session
	return session, nil
}

func (m *memoryRefreshStore) GetByHash(ctx context.Context, tokenHash string) (sqlc.AdminRefreshSession, error) {
	session, ok := m.byHash[tokenHash]
	if !ok {
		return sqlc.AdminRefreshSession{}, repository.ErrRefreshSessionNotFound
	}
	return session, nil
}

func (m *memoryRefreshStore) Rotate(ctx context.Context, sessionID int64, replacedByHash string) error {
	for hash, session := range m.byHash {
		if session.ID == sessionID {
			session.RevokedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
			session.ReplacedByHash = &replacedByHash
			m.byHash[hash] = session
			return nil
		}
	}
	return repository.ErrRefreshSessionNotFound
}

func (m *memoryRefreshStore) Revoke(ctx context.Context, sessionID int64) error {
	for hash, session := range m.byHash {
		if session.ID == sessionID {
			session.RevokedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
			m.byHash[hash] = session
			return nil
		}
	}
	return repository.ErrRefreshSessionNotFound
}

func (m *memoryRefreshStore) RevokeAllForAdmin(ctx context.Context, adminID int64) error {
	for hash, session := range m.byHash {
		if session.AdminID == adminID && !session.RevokedAt.Valid {
			session.RevokedAt = pgtype.Timestamptz{Time: time.Now().UTC(), Valid: true}
			m.byHash[hash] = session
		}
	}
	return nil
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	return string(hash)
}

func activeAdmin(phone string, passwordHash string) sqlc.Admin {
	return sqlc.Admin{
		ID:           3,
		Username:     "admin",
		PasswordHash: passwordHash,
		Name:         "Admin",
		Phone:        &phone,
		Status:       service.AdminStatusActive,
	}
}

func TestAdminAuthService_Login(t *testing.T) {
	phone := "13800000000"
	hash := mustHash(t, "123456")
	access := stubTokenIssuer{token: "access.jwt", expiresIn: 900}
	refresh := &stubRefreshIssuer{
		raw:       "refresh-raw",
		hash:      "refresh-hash",
		expiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		expiresIn: 604800,
	}
	store := newMemoryRefreshStore()

	svc := service.NewAdminAuthService(
		stubAdminReader{admin: activeAdmin(phone, hash)},
		access,
		refresh,
		store,
	)

	got, err := svc.Login(context.Background(), service.LoginInput{Username: "admin", Password: "123456"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if got.AccessToken != "access.jwt" || got.RefreshToken != "refresh-raw" || got.RefreshExpiresIn != 604800 {
		t.Fatalf("unexpected pair: %+v", got)
	}
	if _, err := store.GetByHash(context.Background(), "refresh-hash"); err != nil {
		t.Fatalf("session not stored: %v", err)
	}
}

func TestAdminAuthService_RefreshAndRotation(t *testing.T) {
	phone := "13800000000"
	hash := mustHash(t, "123456")
	access := stubTokenIssuer{token: "access.jwt", expiresIn: 900}
	refresh := &stubRefreshIssuer{
		raw:       "refresh-raw",
		hash:      "refresh-hash",
		expiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		expiresIn: 604800,
	}
	store := newMemoryRefreshStore()
	svc := service.NewAdminAuthService(
		stubAdminReader{admin: activeAdmin(phone, hash)},
		access,
		refresh,
		store,
	)

	login, err := svc.Login(context.Background(), service.LoginInput{Username: "admin", Password: "123456"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	refreshed, err := svc.Refresh(context.Background(), service.RefreshInput{RefreshToken: login.RefreshToken})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if refreshed.RefreshToken == login.RefreshToken {
		t.Fatal("expected rotated refresh token")
	}
	if refreshed.AccessToken == "" {
		t.Fatal("missing access token")
	}

	// Old refresh token reuse should fail and revoke family.
	_, err = svc.Refresh(context.Background(), service.RefreshInput{RefreshToken: login.RefreshToken})
	if !errors.Is(err, service.ErrRefreshTokenReused) {
		t.Fatalf("expected reuse error, got %v", err)
	}

	// Newly issued token should also be revoked after reuse detection.
	_, err = svc.Refresh(context.Background(), service.RefreshInput{RefreshToken: refreshed.RefreshToken})
	if !errors.Is(err, service.ErrRefreshTokenRevoked) {
		t.Fatalf("expected revoked after reuse purge, got %v", err)
	}
}

func TestAdminAuthService_RefreshExpired(t *testing.T) {
	phone := "13800000000"
	hash := mustHash(t, "123456")
	access := stubTokenIssuer{token: "access.jwt", expiresIn: 900}
	refresh := &stubRefreshIssuer{
		raw:       "refresh-raw",
		hash:      "refresh-hash",
		expiresAt: time.Now().UTC().Add(-time.Hour),
		expiresIn: 604800,
	}
	store := newMemoryRefreshStore()
	svc := service.NewAdminAuthService(
		stubAdminReader{admin: activeAdmin(phone, hash)},
		access,
		refresh,
		store,
	)
	login, err := svc.Login(context.Background(), service.LoginInput{Username: "admin", Password: "123456"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	_, err = svc.Refresh(context.Background(), service.RefreshInput{RefreshToken: login.RefreshToken})
	if !errors.Is(err, service.ErrRefreshTokenExpired) {
		t.Fatalf("expected expired, got %v", err)
	}
}

func TestAdminAuthService_LogoutThenRefresh(t *testing.T) {
	phone := "13800000000"
	hash := mustHash(t, "123456")
	access := stubTokenIssuer{token: "access.jwt", expiresIn: 900}
	refresh := &stubRefreshIssuer{
		raw:       "refresh-raw",
		hash:      "refresh-hash",
		expiresAt: time.Now().UTC().Add(7 * 24 * time.Hour),
		expiresIn: 604800,
	}
	store := newMemoryRefreshStore()
	svc := service.NewAdminAuthService(
		stubAdminReader{admin: activeAdmin(phone, hash)},
		access,
		refresh,
		store,
	)
	login, err := svc.Login(context.Background(), service.LoginInput{Username: "admin", Password: "123456"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if err := svc.Logout(context.Background(), service.LogoutInput{RefreshToken: login.RefreshToken}); err != nil {
		t.Fatalf("logout: %v", err)
	}
	_, err = svc.Refresh(context.Background(), service.RefreshInput{RefreshToken: login.RefreshToken})
	if !errors.Is(err, service.ErrRefreshTokenRevoked) {
		t.Fatalf("expected revoked, got %v", err)
	}
}

func TestAdminAuthService_GetMe_GroupsRestaurantsAndRoles(t *testing.T) {
	phone := "13800000000"
	reader := stubAdminReader{
		admin: sqlc.Admin{
			ID:       3,
			Username: "admin",
			Name:     "Admin",
			Phone:    &phone,
			Status:   service.AdminStatusActive,
		},
		restaurantRoles: []sqlc.ListAdminRestaurantRolesRow{
			{
				RestaurantID:   1,
				RestaurantCode: "TEST001",
				RestaurantName: "Test Restaurant",
				RoleID:         10,
				RoleCode:       "superadmin",
				RoleName:       "Super Admin",
			},
			{
				RestaurantID:   1,
				RestaurantCode: "TEST001",
				RestaurantName: "Test Restaurant",
				RoleID:         11,
				RoleCode:       "restaurantadmin",
				RoleName:       "Restaurant Admin",
			},
		},
	}

	svc := service.NewAdminAuthService(reader, stubTokenIssuer{}, &stubRefreshIssuer{}, newMemoryRefreshStore())
	got, err := svc.GetMe(context.Background(), 3)
	if err != nil {
		t.Fatalf("GetMe: %v", err)
	}
	if len(got.Restaurants) != 1 || len(got.Restaurants[0].Roles) != 2 {
		t.Fatalf("unexpected me: %+v", got)
	}
}
