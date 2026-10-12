package repository

import (
	"context"

	"restaurant-api/db/sqlc"
)

type AuthorizationRepository struct {
	q *sqlc.Queries
}

func NewAuthorizationRepository(q *sqlc.Queries) *AuthorizationRepository {
	return &AuthorizationRepository{q: q}
}

func (r *AuthorizationRepository) HasRestaurantMembership(ctx context.Context, adminID, restaurantID int64) (bool, error) {
	return r.q.HasAdminRestaurantMembership(ctx, sqlc.HasAdminRestaurantMembershipParams{
		AdminID:      adminID,
		RestaurantID: restaurantID,
	})
}

func (r *AuthorizationRepository) HasPermissionInRestaurant(ctx context.Context, adminID, restaurantID int64, permissionCode string) (bool, error) {
	return r.q.AdminHasPermissionInRestaurant(ctx, sqlc.AdminHasPermissionInRestaurantParams{
		AdminID:        adminID,
		RestaurantID:   restaurantID,
		PermissionCode: permissionCode,
	})
}
