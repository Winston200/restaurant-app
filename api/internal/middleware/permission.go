package middleware

import (
	"context"
	"errors"
	"net/http"
	"strconv"

	"restaurant-api/internal/auth"
	"restaurant-api/internal/response"
	"restaurant-api/internal/service"
)

type permissionAuthorizer interface {
	Authorize(ctx context.Context, adminID, restaurantID int64, permissionCode string) error
}

// RequirePermission ensures the authenticated admin has permissionCode
// for the restaurant identified by path value {restaurant_id}.
// Must run after RequireAdminJWT.
func RequirePermission(authorizer permissionAuthorizer, permissionCode string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			adminID, ok := auth.AdminIDFromContext(r.Context())
			if !ok {
				response.Fail(w, http.StatusUnauthorized, 40102, "unauthorized")
				return
			}

			rawRestaurantID := r.PathValue("restaurant_id")
			restaurantID, err := strconv.ParseInt(rawRestaurantID, 10, 64)
			if err != nil || restaurantID <= 0 {
				response.Fail(w, http.StatusBadRequest, 40002, "invalid restaurant_id")
				return
			}

			if err := authorizer.Authorize(r.Context(), adminID, restaurantID, permissionCode); err != nil {
				switch {
				case errors.Is(err, service.ErrNoRestaurantAccess), errors.Is(err, service.ErrPermissionDenied):
					response.Fail(w, http.StatusForbidden, 40302, "forbidden")
				default:
					response.Fail(w, http.StatusInternalServerError, 50000, "internal server error")
				}
				return
			}

			ctx := auth.ContextWithRestaurantID(r.Context(), restaurantID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
