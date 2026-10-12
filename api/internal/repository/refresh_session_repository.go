package repository

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"restaurant-api/db/sqlc"
)

var ErrRefreshSessionNotFound = errors.New("refresh session not found")

type RefreshSessionRepository struct {
	q *sqlc.Queries
}

func NewRefreshSessionRepository(q *sqlc.Queries) *RefreshSessionRepository {
	return &RefreshSessionRepository{q: q}
}

func (r *RefreshSessionRepository) Create(ctx context.Context, adminID int64, tokenHash string, expiresAt time.Time) (sqlc.AdminRefreshSession, error) {
	return r.q.CreateAdminRefreshSession(ctx, sqlc.CreateAdminRefreshSessionParams{
		AdminID:   adminID,
		TokenHash: tokenHash,
		ExpiresAt: pgtype.Timestamptz{Time: expiresAt.UTC(), Valid: true},
	})
}

func (r *RefreshSessionRepository) GetByHash(ctx context.Context, tokenHash string) (sqlc.AdminRefreshSession, error) {
	session, err := r.q.GetAdminRefreshSessionByHash(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.AdminRefreshSession{}, ErrRefreshSessionNotFound
		}
		return sqlc.AdminRefreshSession{}, err
	}
	return session, nil
}

func (r *RefreshSessionRepository) Rotate(ctx context.Context, sessionID int64, replacedByHash string) error {
	return r.q.RotateAdminRefreshSession(ctx, sqlc.RotateAdminRefreshSessionParams{
		ID:             sessionID,
		ReplacedByHash: &replacedByHash,
	})
}

func (r *RefreshSessionRepository) Revoke(ctx context.Context, sessionID int64) error {
	return r.q.RevokeAdminRefreshSession(ctx, sessionID)
}

func (r *RefreshSessionRepository) RevokeAllForAdmin(ctx context.Context, adminID int64) error {
	return r.q.RevokeAllAdminRefreshSessions(ctx, adminID)
}
