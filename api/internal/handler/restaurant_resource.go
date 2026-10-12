package handler

import (
	"net/http"

	"restaurant-api/internal/auth"
	"restaurant-api/internal/response"
)

// RestaurantResourceHandler provides placeholder endpoints protected by RBAC.
type RestaurantResourceHandler struct{}

func NewRestaurantResourceHandler() *RestaurantResourceHandler {
	return &RestaurantResourceHandler{}
}

func (h *RestaurantResourceHandler) ListOrders(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r, "orders")
}

func (h *RestaurantResourceHandler) ListCategories(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r, "categories")
}

func (h *RestaurantResourceHandler) ListTables(w http.ResponseWriter, r *http.Request) {
	h.ok(w, r, "tables")
}

func (h *RestaurantResourceHandler) ok(w http.ResponseWriter, r *http.Request, resource string) {
	adminID, _ := auth.AdminIDFromContext(r.Context())
	restaurantID, _ := auth.RestaurantIDFromContext(r.Context())
	response.OK(w, map[string]interface{}{
		"resource":      resource,
		"admin_id":      adminID,
		"restaurant_id": restaurantID,
	})
}
