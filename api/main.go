package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"restaurant-api/db/sqlc"
	authjwt "restaurant-api/internal/auth/jwt"
	"restaurant-api/internal/auth/refreshtoken"
	"restaurant-api/internal/config"
	"restaurant-api/internal/handler"
	"restaurant-api/internal/middleware"
	"restaurant-api/internal/rbac"
	"restaurant-api/internal/repository"
	"restaurant-api/internal/response"
	"restaurant-api/internal/service"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping database: %v", err)
	}

	tokenMgr, err := authjwt.NewAccessTokenManager(cfg.JWTAccessSecret, cfg.JWTAccessTTL, cfg.JWTIssuer)
	if err != nil {
		log.Fatalf("init jwt: %v", err)
	}
	refreshMgr, err := refreshtoken.NewManager(cfg.JWTRefreshSecret, cfg.JWTRefreshTTL)
	if err != nil {
		log.Fatalf("init refresh token: %v", err)
	}

	queries := sqlc.New(pool)
	adminRepo := repository.NewAdminRepository(queries)
	authzRepo := repository.NewAuthorizationRepository(queries)
	refreshRepo := repository.NewRefreshSessionRepository(queries)
	adminAuth := service.NewAdminAuthService(
		adminRepo,
		accessTokenIssuer{mgr: tokenMgr},
		refreshMgr,
		refreshRepo,
	)
	authz := service.NewAuthorizationService(authzRepo)
	adminHandler := handler.NewAdminHandler(adminAuth)
	resourceHandler := handler.NewRestaurantResourceHandler()

	requireAdmin := middleware.RequireAdminJWT(tokenMgr)
	protect := func(permission string, h http.Handler) http.Handler {
		return requireAdmin(middleware.RequirePermission(authz, permission)(h))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		response.OK(w, map[string]string{
			"status":  "ok",
			"service": "api",
		})
	})
	// Nginx strips /api:
	// POST /api/admin/login|refresh|logout
	// GET  /api/admin/me
	// GET  /api/admin/restaurants/{restaurant_id}/orders|categories|tables
	mux.HandleFunc("POST /admin/login", adminHandler.Login)
	mux.HandleFunc("POST /admin/refresh", adminHandler.Refresh)
	mux.HandleFunc("POST /admin/logout", adminHandler.Logout)
	mux.Handle("GET /admin/me", requireAdmin(http.HandlerFunc(adminHandler.Me)))
	mux.Handle("GET /admin/restaurants/{restaurant_id}/orders", protect(rbac.OrderManage, http.HandlerFunc(resourceHandler.ListOrders)))
	mux.Handle("GET /admin/restaurants/{restaurant_id}/categories", protect(rbac.CategoryManage, http.HandlerFunc(resourceHandler.ListCategories)))
	mux.Handle("GET /admin/restaurants/{restaurant_id}/tables", protect(rbac.TableManage, http.HandlerFunc(resourceHandler.ListTables)))

	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", cfg.Port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		log.Printf("restaurant_api listening on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %v", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdownCtx)
}

type accessTokenIssuer struct {
	mgr *authjwt.AccessTokenManager
}

func (t accessTokenIssuer) IssueAccessToken(adminID int64) (string, int64, error) {
	issued, err := t.mgr.IssueAccessToken(adminID)
	if err != nil {
		return "", 0, err
	}
	return issued.Token, issued.ExpiresIn, nil
}
