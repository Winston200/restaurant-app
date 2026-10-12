package rbac

// Permission codes must match permissions.code in the database.
const (
	SuperAdminAccess     = "superadmin.access"
	RestaurantAdminAccess = "restaurantadmin.access"
	OrderManage          = "order.manage"
	CategoryManage       = "category.manage"
	TableManage          = "table.manage"
)
