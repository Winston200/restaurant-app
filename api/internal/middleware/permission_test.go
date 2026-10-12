package middleware_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"restaurant-api/internal/auth"
	authjwt "restaurant-api/internal/auth/jwt"
	"restaurant-api/internal/middleware"
	"restaurant-api/internal/rbac"
	"restaurant-api/internal/service"
)

type stubAuthorizer struct {
	err           error
	gotAdminID    int64
	gotRestaurant int64
	gotPermission string
}

func (s *stubAuthorizer) Authorize(ctx context.Context, adminID, restaurantID int64, permissionCode string) error {
	s.gotAdminID = adminID
	s.gotRestaurant = restaurantID
	s.gotPermission = permissionCode
	return s.err
}

func withAdminID(r *http.Request, adminID int64) *http.Request {
	return r.WithContext(auth.ContextWithAdminID(r.Context(), adminID))
}

func TestRequirePermission(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		restaurantID, ok := auth.RestaurantIDFromContext(r.Context())
		if !ok {
			t.Fatalf("restaurant_id missing from context")
		}
		_ = json.NewEncoder(w).Encode(map[string]int64{"restaurant_id": restaurantID})
	})

	t.Run("no admin in context is 401", func(t *testing.T) {
		authz := &stubAuthorizer{}
		h := middleware.RequirePermission(authz, rbac.OrderManage)(next)
		req := httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil)
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("invalid restaurant_id is 400", func(t *testing.T) {
		authz := &stubAuthorizer{}
		h := middleware.RequirePermission(authz, rbac.OrderManage)(next)
		req := withAdminID(httptest.NewRequest(http.MethodGet, "/admin/restaurants/x/orders", nil), 3)
		req.SetPathValue("restaurant_id", "x")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("no restaurant relationship is 403", func(t *testing.T) {
		authz := &stubAuthorizer{err: service.ErrNoRestaurantAccess}
		h := middleware.RequirePermission(authz, rbac.OrderManage)(next)
		req := withAdminID(httptest.NewRequest(http.MethodGet, "/admin/restaurants/9/orders", nil), 3)
		req.SetPathValue("restaurant_id", "9")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("no permission is 403", func(t *testing.T) {
		authz := &stubAuthorizer{err: service.ErrPermissionDenied}
		h := middleware.RequirePermission(authz, rbac.OrderManage)(next)
		req := withAdminID(httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil), 3)
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	for _, code := range []string{rbac.OrderManage, rbac.CategoryManage, rbac.TableManage} {
		t.Run("allow_"+code, func(t *testing.T) {
			authz := &stubAuthorizer{}
			h := middleware.RequirePermission(authz, code)(next)
			req := withAdminID(httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/resource", nil), 3)
			req.SetPathValue("restaurant_id", "1")
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
			}
			if authz.gotAdminID != 3 || authz.gotRestaurant != 1 || authz.gotPermission != code {
				t.Fatalf("authorize args = admin=%d restaurant=%d perm=%s", authz.gotAdminID, authz.gotRestaurant, authz.gotPermission)
			}
		})
	}
}

func TestJWTThenPermissionChain(t *testing.T) {
	mgr, err := authjwt.NewAccessTokenManager("test-secret-at-least-32-chars-long", 15*time.Minute, "restaurant-api")
	if err != nil {
		t.Fatalf("jwt: %v", err)
	}
	issued, err := mgr.IssueAccessToken(3)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	authz := &stubAuthorizer{}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := middleware.RequireAdminJWT(mgr)(
		middleware.RequirePermission(authz, rbac.OrderManage)(next),
	)

	t.Run("missing token 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil)
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("invalid token 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil)
		req.Header.Set("Authorization", "Bearer not-a-valid-token")
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("valid token but denied 403", func(t *testing.T) {
		authz.err = service.ErrPermissionDenied
		req := httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d", rec.Code)
		}
	})

	t.Run("valid token and allowed 200", func(t *testing.T) {
		authz.err = nil
		req := httptest.NewRequest(http.MethodGet, "/admin/restaurants/1/orders", nil)
		req.Header.Set("Authorization", "Bearer "+issued.Token)
		req.SetPathValue("restaurant_id", "1")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d", rec.Code)
		}
		if authz.gotAdminID != 3 || authz.gotRestaurant != 1 {
			t.Fatalf("unexpected authorize args: %+v", authz)
		}
	})
}
