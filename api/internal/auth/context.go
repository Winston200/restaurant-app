package auth

import "context"

type contextKey string

const (
	adminIDKey      contextKey = "admin_id"
	restaurantIDKey contextKey = "restaurant_id"
)

func ContextWithAdminID(ctx context.Context, adminID int64) context.Context {
	return context.WithValue(ctx, adminIDKey, adminID)
}

func AdminIDFromContext(ctx context.Context) (int64, bool) {
	adminID, ok := ctx.Value(adminIDKey).(int64)
	if !ok || adminID <= 0 {
		return 0, false
	}
	return adminID, true
}

func ContextWithRestaurantID(ctx context.Context, restaurantID int64) context.Context {
	return context.WithValue(ctx, restaurantIDKey, restaurantID)
}

func RestaurantIDFromContext(ctx context.Context) (int64, bool) {
	restaurantID, ok := ctx.Value(restaurantIDKey).(int64)
	if !ok || restaurantID <= 0 {
		return 0, false
	}
	return restaurantID, true
}
