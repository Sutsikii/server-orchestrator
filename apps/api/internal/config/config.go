package config

import (
	"os"
	"time"
)

type Config struct {
	Port             string
	JWTSecret        string
	JWTAccessExpiry  time.Duration
	JWTRefreshExpiry time.Duration
	DatabaseURL      string
	AllowedOrigins   []string
}

func Load() (*Config, error) {
	accessExpiry, err := time.ParseDuration(getEnv("JWT_ACCESS_EXPIRY", "15m"))
	if err != nil {
		return nil, err
	}

	refreshExpiry, err := time.ParseDuration(getEnv("JWT_REFRESH_EXPIRY", "168h"))
	if err != nil {
		return nil, err
	}

	origins := splitOrigins(getEnv("ALLOWED_ORIGINS", "http://localhost:3000"))

	return &Config{
		Port:             getEnv("PORT", "8085"),
		JWTSecret:        getEnv("JWT_SECRET", "change-me-super-secret-256-bits"),
		JWTAccessExpiry:  accessExpiry,
		JWTRefreshExpiry: refreshExpiry,
		DatabaseURL:      getEnv("DATABASE_URL", ""),
		AllowedOrigins:   origins,
	}, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func splitOrigins(s string) []string {
	var result []string
	start := 0
	for i := 0; i <= len(s); i++ {
		if i == len(s) || s[i] == ',' {
			part := trim(s[start:i])
			if part != "" {
				result = append(result, part)
			}
			start = i + 1
		}
	}
	return result
}

func trim(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t') {
		s = s[:len(s)-1]
	}
	return s
}
