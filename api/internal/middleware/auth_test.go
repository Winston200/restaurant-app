package middleware_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"restaurant-api/internal/auth"
	authjwt "restaurant-api/internal/auth/jwt"
	"restaurant-api/internal/middleware"
)

func TestRequireAdminJWT(t *testing.T) {
	mgr, err := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "restaurant-api")
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminID, ok := auth.AdminIDFromContext(r.Context())
		if !ok {
			t.Fatalf("admin_id missing from context")
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"admin_id": adminID})
	})
	h := middleware.RequireAdminJWT(mgr)(next)

	t.Run("missing authorization", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Token abc")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("bad signature", func(t *testing.T) {
		other, _ := authjwt.NewAccessTokenManager("other-secret-at-least-32-chars-xxx", 15*time.Minute, "restaurant-api")
		issued, err := other.IssueAccessToken(7)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("expired token", func(t *testing.T) {
		mgr.SetNowFunc(func() time.Time {
			return time.Now().UTC().Add(-2 * time.Hour)
		})
		issued, err := mgr.IssueAccessToken(7)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		mgr.SetNowFunc(time.Now)

		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		badIssuer, _ := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "other-issuer")
		issued, err := badIssuer.IssueAccessToken(7)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("valid token", func(t *testing.T) {
		issued, err := mgr.IssueAccessToken(42)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		req := httptest.NewRequest(http.MethodGet, "/admin/me", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
		}
		var body map[string]int64
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if body["admin_id"] != 42 {
			t.Fatalf("admin_id = %d", body["admin_id"])
		}
	})
}
