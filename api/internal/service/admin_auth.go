package service

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"restaurant-api/db/sqlc"
	"restaurant-api/internal/repository"
)

const (
	AdminStatusActive int16 = 1
)

var (
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAdminDisabled       = errors.New("admin disabled")
	ErrValidation          = errors.New("validation error")
	ErrTokenIssue          = errors.New("token issue failed")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("refresh token expired")
	ErrRefreshTokenRevoked = errors.New("refresh token revoked")
	ErrRefreshTokenReused  = errors.New("refresh token reused")
)

type AdminReader interface {
	GetByLogin(ctx context.Context, login string) (sqlc.Admin, error)
	GetByID(ctx context.Context, id int64) (sqlc.Admin, error)
	ListRestaurantRoles(ctx context.Context, adminID int64) ([]sqlc.ListAdminRestaurantRolesRow, error)
}

type AccessTokenIssuer interface {
	IssueAccessToken(adminID int64) (token string, expiresIn int64, err error)
}

type RefreshTokenIssuer interface {
	Issue() (rawToken string, tokenHash string, expiresAt time.Time, expiresIn int64, err error)
	Hash(rawToken string) string
}

type RefreshSessionStore interface {
	Create(ctx context.Context, adminID int64, tokenHash string, expiresAt time.Time) (sqlc.AdminRefreshSession, error)
	GetByHash(ctx context.Context, tokenHash string) (sqlc.AdminRefreshSession, error)
	Rotate(ctx context.Context, sessionID int64, replacedByHash string) error
	Revoke(ctx context.Context, sessionID int64) error
	RevokeAllForAdmin(ctx context.Context, adminID int64) error
}

type AdminAuthService struct {
	admins          AdminReader
	accessTokens    AccessTokenIssuer
	refreshTokens   RefreshTokenIssuer
	refreshSessions RefreshSessionStore
	now             func() time.Time
}

func NewAdminAuthService(
	admins AdminReader,
	accessTokens AccessTokenIssuer,
	refreshTokens RefreshTokenIssuer,
	refreshSessions RefreshSessionStore,
) *AdminAuthService {
	return &AdminAuthService{
		admins:          admins,
		accessTokens:    accessTokens,
		refreshTokens:   refreshTokens,
		refreshSessions: refreshSessions,
		now:             time.Now,
	}
}

func (s *AdminAuthService) SetNowFunc(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

type LoginInput struct {
	Username string
	Password string
}

type LoginAdmin struct {
	ID    string  `json:"id"`
	Phone *string `json:"phone"`
}

type TokenPair struct {
	AccessToken      string     `json:"access_token"`
	RefreshToken     string     `json:"refresh_token"`
	TokenType        string     `json:"token_type"`
	ExpiresIn        int64      `json:"expires_in"`
	RefreshExpiresIn int64      `json:"refresh_expires_in"`
	Admin            LoginAdmin `json:"admin,omitempty"`
}

type LoginResult = TokenPair

func (s *AdminAuthService) Login(ctx context.Context, in LoginInput) (*LoginResult, error) {
	username := strings.TrimSpace(in.Username)
	password := in.Password

	if username == "" || password == "" {
		return nil, ErrValidation
	}

	admin, err := s.admins.GetByLogin(ctx, username)
	if err != nil {
		if errors.Is(err, repository.ErrAdminNotFound) {
			_ = bcrypt.CompareHashAndPassword(dummyBcryptHash, []byte(password))
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(admin.PasswordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	if admin.Status != AdminStatusActive {
		return nil, ErrAdminDisabled
	}

	return s.issueTokenPair(ctx, admin)
}

type RefreshInput struct {
	RefreshToken string
}

func (s *AdminAuthService) Refresh(ctx context.Context, in RefreshInput) (*TokenPair, error) {
	raw := strings.TrimSpace(in.RefreshToken)
	if raw == "" {
		return nil, ErrValidation
	}

	tokenHash := s.refreshTokens.Hash(raw)
	session, err := s.refreshSessions.GetByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshSessionNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}

	if session.RevokedAt.Valid {
		// Reuse of a rotated token is treated as theft: revoke all sessions for this admin.
		if session.ReplacedByHash != nil && *session.ReplacedByHash != "" {
			_ = s.refreshSessions.RevokeAllForAdmin(ctx, session.AdminID)
			return nil, ErrRefreshTokenReused
		}
		return nil, ErrRefreshTokenRevoked
	}

	if !session.ExpiresAt.Valid || !session.ExpiresAt.Time.After(s.now().UTC()) {
		_ = s.refreshSessions.Revoke(ctx, session.ID)
		return nil, ErrRefreshTokenExpired
	}

	admin, err := s.admins.GetByID(ctx, session.AdminID)
	if err != nil {
		if errors.Is(err, repository.ErrAdminNotFound) {
			return nil, ErrInvalidRefreshToken
		}
		return nil, err
	}
	if admin.Status != AdminStatusActive {
		_ = s.refreshSessions.RevokeAllForAdmin(ctx, admin.ID)
		return nil, ErrAdminDisabled
	}

	newRaw, newHash, newExpiresAt, newExpiresIn, err := s.refreshTokens.Issue()
	if err != nil {
		return nil, errors.Join(ErrTokenIssue, err)
	}

	if err := s.refreshSessions.Rotate(ctx, session.ID, newHash); err != nil {
		return nil, err
	}
	if _, err := s.refreshSessions.Create(ctx, admin.ID, newHash, newExpiresAt); err != nil {
		return nil, err
	}

	accessToken, accessExpiresIn, err := s.accessTokens.IssueAccessToken(admin.ID)
	if err != nil {
		return nil, errors.Join(ErrTokenIssue, err)
	}

	return &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     newRaw,
		TokenType:        "Bearer",
		ExpiresIn:        accessExpiresIn,
		RefreshExpiresIn: newExpiresIn,
		Admin: LoginAdmin{
			ID:    strconv.FormatInt(admin.ID, 10),
			Phone: admin.Phone,
		},
	}, nil
}

type LogoutInput struct {
	RefreshToken string
}

func (s *AdminAuthService) Logout(ctx context.Context, in LogoutInput) error {
	raw := strings.TrimSpace(in.RefreshToken)
	if raw == "" {
		return ErrValidation
	}

	tokenHash := s.refreshTokens.Hash(raw)
	session, err := s.refreshSessions.GetByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, repository.ErrRefreshSessionNotFound) {
			// Idempotent logout: unknown token is treated as already logged out.
			return nil
		}
		return err
	}

	if session.RevokedAt.Valid {
		return nil
	}
	return s.refreshSessions.Revoke(ctx, session.ID)
}

func (s *AdminAuthService) issueTokenPair(ctx context.Context, admin sqlc.Admin) (*TokenPair, error) {
	accessToken, accessExpiresIn, err := s.accessTokens.IssueAccessToken(admin.ID)
	if err != nil {
		return nil, errors.Join(ErrTokenIssue, err)
	}

	raw, hash, expiresAt, refreshExpiresIn, err := s.refreshTokens.Issue()
	if err != nil {
		return nil, errors.Join(ErrTokenIssue, err)
	}

	if _, err := s.refreshSessions.Create(ctx, admin.ID, hash, expiresAt); err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:      accessToken,
		RefreshToken:     raw,
		TokenType:        "Bearer",
		ExpiresIn:        accessExpiresIn,
		RefreshExpiresIn: refreshExpiresIn,
		Admin: LoginAdmin{
			ID:    strconv.FormatInt(admin.ID, 10),
			Phone: admin.Phone,
		},
	}, nil
}

type AdminMeRole struct {
	RoleID   string `json:"role_id"`
	RoleCode string `json:"role_code"`
	RoleName string `json:"role_name"`
}

type AdminMeRestaurant struct {
	RestaurantID   string        `json:"restaurant_id"`
	RestaurantCode string        `json:"restaurant_code"`
	RestaurantName string        `json:"restaurant_name"`
	Roles          []AdminMeRole `json:"roles"`
}

type AdminMe struct {
	ID          string              `json:"id"`
	Username    string              `json:"username"`
	Name        string              `json:"name"`
	Phone       *string             `json:"phone"`
	Status      int16               `json:"status"`
	Restaurants []AdminMeRestaurant `json:"restaurants"`
}

func (s *AdminAuthService) GetMe(ctx context.Context, adminID int64) (*AdminMe, error) {
	if adminID <= 0 {
		return nil, ErrValidation
	}

	admin, err := s.admins.GetByID(ctx, adminID)
	if err != nil {
		if errors.Is(err, repository.ErrAdminNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if admin.Status != AdminStatusActive {
		return nil, ErrAdminDisabled
	}

	rows, err := s.admins.ListRestaurantRoles(ctx, adminID)
	if err != nil {
		return nil, err
	}

	return &AdminMe{
		ID:          strconv.FormatInt(admin.ID, 10),
		Username:    admin.Username,
		Name:        admin.Name,
		Phone:       admin.Phone,
		Status:      admin.Status,
		Restaurants: groupAdminRestaurantRoles(rows),
	}, nil
}

func groupAdminRestaurantRoles(rows []sqlc.ListAdminRestaurantRolesRow) []AdminMeRestaurant {
	if len(rows) == 0 {
		return []AdminMeRestaurant{}
	}

	ordered := make([]AdminMeRestaurant, 0)
	indexByRestaurantID := make(map[int64]int)

	for _, row := range rows {
		idx, ok := indexByRestaurantID[row.RestaurantID]
		if !ok {
			ordered = append(ordered, AdminMeRestaurant{
				RestaurantID:   strconv.FormatInt(row.RestaurantID, 10),
				RestaurantCode: row.RestaurantCode,
				RestaurantName: row.RestaurantName,
				Roles:          []AdminMeRole{},
			})
			idx = len(ordered) - 1
			indexByRestaurantID[row.RestaurantID] = idx
		}

		ordered[idx].Roles = append(ordered[idx].Roles, AdminMeRole{
			RoleID:   strconv.FormatInt(row.RoleID, 10),
			RoleCode: row.RoleCode,
			RoleName: row.RoleName,
		})
	}

	return ordered
}

// bcrypt hash of a fixed string; used only to keep login timing closer when user is missing.
var dummyBcryptHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
