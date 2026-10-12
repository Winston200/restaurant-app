package service

import (
	"context"
	"errors"
)

var (
	ErrNoRestaurantAccess = errors.New("no restaurant access")
	ErrPermissionDenied   = errors.New("permission denied")
)

type MembershipChecker interface {
	HasRestaurantMembership(ctx context.Context, adminID, restaurantID int64) (bool, error)
	HasPermissionInRestaurant(ctx context.Context, adminID, restaurantID int64, permissionCode string) (bool, error)
}

type AuthorizationService struct {
	store MembershipChecker
}

func NewAuthorizationService(store MembershipChecker) *AuthorizationService {
	return &AuthorizationService{store: store}
}

// Authorize verifies admin ↔ restaurant membership via restaurant_admins,
// then checks that at least one of the admin's roles in that restaurant
// grants the required permission through role_has_permissions.
// There is no hardcoded superadmin bypass; privileges come only from DB data.
func (s *AuthorizationService) Authorize(ctx context.Context, adminID, restaurantID int64, permissionCode string) error {
	if adminID <= 0 || restaurantID <= 0 || permissionCode == "" {
		return ErrPermissionDenied
	}

	hasMembership, err := s.store.HasRestaurantMembership(ctx, adminID, restaurantID)
	if err != nil {
		return err
	}
	if !hasMembership {
		return ErrNoRestaurantAccess
	}

	hasPermission, err := s.store.HasPermissionInRestaurant(ctx, adminID, restaurantID, permissionCode)
	if err != nil {
		return err
	}
	if !hasPermission {
		return ErrPermissionDenied
	}
	return nil
}
