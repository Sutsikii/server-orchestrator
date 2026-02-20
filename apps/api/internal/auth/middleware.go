package auth

import (
	"context"
	"net/http"
	"strings"

	"server-orchestrator/internal/user"
)

type contextKey string

const userContextKey contextKey = "user"

type userLoader interface {
	FindByID(ctx context.Context, id string) (*user.User, error)
}

func AuthRequired(jwtSecret string, repo userLoader) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "missing or invalid authorization header")
				return
			}

			tokenStr := strings.TrimPrefix(header, "Bearer ")
			claims, err := ValidateToken(tokenStr, jwtSecret)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "invalid or expired token")
				return
			}

			u, err := repo.FindByID(r.Context(), claims.UserID)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "user not found")
				return
			}

			ctx := context.WithValue(r.Context(), userContextKey, u)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func UserFromContext(ctx context.Context) *user.User {
	u, _ := ctx.Value(userContextKey).(*user.User)
	return u
}
