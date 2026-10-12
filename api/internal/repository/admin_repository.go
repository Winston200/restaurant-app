package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"restaurant-api/db/sqlc"
)

var ErrAdminNotFound = errors.New("admin not found")

type AdminRepository struct {
	q *sqlc.Queries
}

func NewAdminRepository(q *sqlc.Queries) *AdminRepository {
	return &AdminRepository{q: q}
}

func (r *AdminRepository) GetByLogin(ctx context.Context, login string) (sqlc.Admin, error) {
	admin, err := r.q.GetAdminByLogin(ctx, login)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.Admin{}, ErrAdminNotFound
		}
		return sqlc.Admin{}, err
	}
	return admin, nil
}

func (r *AdminRepository) GetByID(ctx context.Context, id int64) (sqlc.Admin, error) {
	admin, err := r.q.GetAdminByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return sqlc.Admin{}, ErrAdminNotFound
		}
		return sqlc.Admin{}, err
	}
	return admin, nil
}

func (r *AdminRepository) ListRestaurantRoles(ctx context.Context, adminID int64) ([]sqlc.ListAdminRestaurantRolesRow, error) {
	rows, err := r.q.ListAdminRestaurantRoles(ctx, adminID)
	if err != nil {
		return nil, err
	}
	if rows == nil {
		return []sqlc.ListAdminRestaurantRolesRow{}, nil
	}
	return rows, nil
}
