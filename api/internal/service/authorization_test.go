package service_test

import (
	"context"
	"errors"
	"testing"

	"restaurant-api/internal/service"
)

type stubMembershipChecker struct {
	hasMembership bool
	hasPermission bool
	membershipErr error
	permissionErr error
}

func (s stubMembershipChecker) HasRestaurantMembership(ctx context.Context, adminID, restaurantID int64) (bool, error) {
	return s.hasMembership, s.membershipErr
}

func (s stubMembershipChecker) HasPermissionInRestaurant(ctx context.Context, adminID, restaurantID int64, permissionCode string) (bool, error) {
	return s.hasPermission, s.permissionErr
}

func TestAuthorizationService_Authorize(t *testing.T) {
	tests := []struct {
		name    string
		store   stubMembershipChecker
		wantErr error
	}{
		{
			name:    "no membership",
			store:   stubMembershipChecker{hasMembership: false},
			wantErr: service.ErrNoRestaurantAccess,
		},
		{
			name:    "membership without permission",
			store:   stubMembershipChecker{hasMembership: true, hasPermission: false},
			wantErr: service.ErrPermissionDenied,
		},
		{
			name:    "allowed",
			store:   stubMembershipChecker{hasMembership: true, hasPermission: true},
			wantErr: nil,
		},
		{
			name:    "store error",
			store:   stubMembershipChecker{membershipErr: errors.New("db down")},
			wantErr: errors.New("db down"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := service.NewAuthorizationService(tt.store)
			err := svc.Authorize(context.Background(), 1, 2, "order.manage")
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected %v", tt.wantErr)
			}
			if tt.name == "store error" {
				if err.Error() != tt.wantErr.Error() {
					t.Fatalf("got %v", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("got %v, want %v", err, tt.wantErr)
			}
		})
	}
}
