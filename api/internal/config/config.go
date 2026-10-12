package config

import (
	"fmt"
	"os"
	"time"
)

type Config struct {
	Port             string
	DatabaseURL      string
	JWTAccessSecret  string
	JWTAccessTTL     time.Duration
	JWTIssuer        string
	JWTRefreshSecret string
	JWTRefreshTTL    time.Duration
}

func Load() (Config, error) {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		databaseURL = "postgres://restaurant:restaurant@localhost:5433/restaurant?sslmode=disable"
	}

	accessSecret := os.Getenv("JWT_ACCESS_SECRET")
	if accessSecret == "" {
		return Config{}, fmt.Errorf("JWT_ACCESS_SECRET is required")
	}

	accessTTLRaw := os.Getenv("JWT_ACCESS_EXPIRES_IN")
	if accessTTLRaw == "" {
		accessTTLRaw = "15m"
	}
	accessTTL, err := time.ParseDuration(accessTTLRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid JWT_ACCESS_EXPIRES_IN: %w", err)
	}
	if accessTTL <= 0 {
		return Config{}, fmt.Errorf("JWT_ACCESS_EXPIRES_IN must be positive")
	}

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET")
	if refreshSecret == "" {
		return Config{}, fmt.Errorf("JWT_REFRESH_SECRET is required")
	}

	refreshTTLRaw := os.Getenv("JWT_REFRESH_EXPIRES_IN")
	if refreshTTLRaw == "" {
		refreshTTLRaw = "168h" // 7 days
	}
	refreshTTL, err := time.ParseDuration(refreshTTLRaw)
	if err != nil {
		return Config{}, fmt.Errorf("invalid JWT_REFRESH_EXPIRES_IN: %w", err)
	}
	if refreshTTL <= 0 {
		return Config{}, fmt.Errorf("JWT_REFRESH_EXPIRES_IN must be positive")
	}
	if refreshTTL <= accessTTL {
		return Config{}, fmt.Errorf("JWT_REFRESH_EXPIRES_IN must be greater than JWT_ACCESS_EXPIRES_IN")
	}

	issuer := os.Getenv("JWT_ISSUER")
	if issuer == "" {
		issuer = "restaurant-api"
	}

	return Config{
		Port:             port,
		DatabaseURL:      databaseURL,
		JWTAccessSecret:  accessSecret,
		JWTAccessTTL:     accessTTL,
		JWTIssuer:        issuer,
		JWTRefreshSecret: refreshSecret,
		JWTRefreshTTL:    refreshTTL,
	}, nil
}
