package auth

import (
	"context"
	"errors"
	"time"

	"server-orchestrator/internal/user"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var ErrUnauthorized = errors.New("unauthorized")

type Service struct {
	db            *pgxpool.Pool
	userRepo      *user.Repository
	jwtSecret     string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

func NewService(db *pgxpool.Pool, userRepo *user.Repository, jwtSecret string, accessExpiry, refreshExpiry time.Duration) *Service {
	return &Service{
		db:            db,
		userRepo:      userRepo,
		jwtSecret:     jwtSecret,
		accessExpiry:  accessExpiry,
		refreshExpiry: refreshExpiry,
	}
}

type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (s *Service) Login(ctx context.Context, email, password string) (*user.User, *TokenPair, error) {
	u, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy.hash.to.prevent.timing.attack.padding"), []byte(password)) //nolint:errcheck
		return nil, nil, ErrUnauthorized
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
		return nil, nil, ErrUnauthorized
	}

	pair, err := s.issueTokenPair(ctx, u.ID)
	if err != nil {
		return nil, nil, err
	}

	return u, pair, nil
}

func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*TokenPair, error) {
	claims, err := ValidateToken(rawRefreshToken, s.jwtSecret)
	if err != nil {
		return nil, ErrUnauthorized
	}

	tokenHash := HashToken(rawRefreshToken)

	var expiresAt time.Time
	err = s.db.QueryRow(ctx,
		`SELECT expires_at FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	).Scan(&expiresAt)
	if err != nil || time.Now().After(expiresAt) {
		return nil, ErrUnauthorized
	}

	_, err = s.db.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	)
	if err != nil {
		return nil, err
	}

	pair, err := s.issueTokenPair(ctx, claims.UserID)
	if err != nil {
		return nil, err
	}

	return pair, nil
}

func (s *Service) Logout(ctx context.Context, rawRefreshToken string) error {
	tokenHash := HashToken(rawRefreshToken)
	_, err := s.db.Exec(ctx,
		`DELETE FROM refresh_tokens WHERE token_hash = $1`,
		tokenHash,
	)
	return err
}

func (s *Service) issueTokenPair(ctx context.Context, userID string) (*TokenPair, error) {
	accessToken, err := GenerateToken(userID, s.jwtSecret, s.accessExpiry)
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateToken(userID, s.jwtSecret, s.refreshExpiry)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(s.refreshExpiry)
	tokenHash := HashToken(refreshToken)

	_, err = s.db.Exec(ctx,
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`,
		userID, tokenHash, expiresAt,
	)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresAt:    expiresAt,
	}, nil
}
