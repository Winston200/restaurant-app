package authjwt_test

import (
	"errors"
	"testing"
	"time"

	authjwt "restaurant-api/internal/auth/jwt"
)

func TestIssueAndParseAccessToken(t *testing.T) {
	mgr, err := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "restaurant-api")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	issued, err := mgr.IssueAccessToken(42)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if issued.Token == "" {
		t.Fatal("empty token")
	}
	if issued.ExpiresIn != 900 {
		t.Fatalf("expires_in = %d, want 900", issued.ExpiresIn)
	}

	claims, err := mgr.ParseAccessToken(issued.Token)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if claims.AdminID != 42 {
		t.Fatalf("admin_id = %d, want 42", claims.AdminID)
	}
	if claims.Issuer != "restaurant-api" {
		t.Fatalf("issuer = %q", claims.Issuer)
	}
	if claims.IssuedAt <= 0 || claims.ExpiresAt <= claims.IssuedAt {
		t.Fatalf("invalid timestamps: issued_at=%d expires_at=%d", claims.IssuedAt, claims.ExpiresAt)
	}
	if claims.ExpiresAt-claims.IssuedAt != 900 {
		t.Fatalf("ttl seconds = %d, want 900", claims.ExpiresAt-claims.IssuedAt)
	}
}

func TestParseRejectsExpiredAndWrongIssuer(t *testing.T) {
	mgr, err := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "restaurant-api")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	mgr.SetNowFunc(func() time.Time { return time.Now().UTC().Add(-2 * time.Hour) })
	expired, err := mgr.IssueAccessToken(1)
	if err != nil {
		t.Fatalf("issue expired: %v", err)
	}
	mgr.SetNowFunc(time.Now)
	if _, err := mgr.ParseAccessToken(expired.Token); !errors.Is(err, authjwt.ErrTokenExpired) {
		t.Fatalf("expected expired, got %v", err)
	}

	other, _ := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "other")
	issued, err := other.IssueAccessToken(1)
	if err != nil {
		t.Fatalf("issue other issuer: %v", err)
	}
	if _, err := mgr.ParseAccessToken(issued.Token); !errors.Is(err, authjwt.ErrInvalidIssuer) {
		t.Fatalf("expected invalid issuer, got %v", err)
	}
}

func TestNewAccessTokenManagerRequiresSecret(t *testing.T) {
	_, err := authjwt.NewAccessTokenManager("", time.Minute, "restaurant-api")
	if err == nil {
		t.Fatal("expected error for empty secret")
	}
}
