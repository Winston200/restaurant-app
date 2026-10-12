package middleware

import (
	"net/http"
	"strings"

	"restaurant-api/internal/auth"
	authjwt "restaurant-api/internal/auth/jwt"
	"restaurant-api/internal/response"
)

type tokenParser interface {
	ParseAccessToken(tokenString string) (*authjwt.AccessClaims, error)
}

// RequireAdminJWT validates Bearer Access Tokens and injects admin_id into context.
func RequireAdminJWT(parser tokenParser) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if header == "" {
				response.Fail(w, http.StatusUnauthorized, 40102, "missing authorization")
				return
			}

			parts := strings.SplitN(header, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || strings.TrimSpace(parts[1]) == "" {
				response.Fail(w, http.StatusUnauthorized, 40103, "invalid authorization format")
				return
			}

			claims, err := parser.ParseAccessToken(strings.TrimSpace(parts[1]))
			if err != nil {
				// Do not log the raw token.
				response.Fail(w, http.StatusUnauthorized, 40104, "unauthorized")
				return
			}

			ctx := auth.ContextWithAdminID(r.Context(), claims.AdminID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
