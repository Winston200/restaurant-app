-- name: HasAdminRestaurantMembership :one
SELECT EXISTS (
    SELECT 1
    FROM restaurant_admins ra
    INNER JOIN restaurants rest ON rest.id = ra.restaurant_id
    INNER JOIN roles r ON r.id = ra.role_id
    WHERE ra.admin_id = sqlc.arg(admin_id)
      AND ra.restaurant_id = sqlc.arg(restaurant_id)
      AND rest.status = 1
      AND r.status = 1
) AS has_membership;

-- name: AdminHasPermissionInRestaurant :one
SELECT EXISTS (
    SELECT 1
    FROM restaurant_admins ra
    INNER JOIN restaurants rest ON rest.id = ra.restaurant_id
    INNER JOIN roles r ON r.id = ra.role_id
    INNER JOIN role_has_permissions rhp ON rhp.role_id = r.id
    INNER JOIN permissions p ON p.id = rhp.permission_id
    WHERE ra.admin_id = sqlc.arg(admin_id)
      AND ra.restaurant_id = sqlc.arg(restaurant_id)
      AND p.code = sqlc.arg(permission_code)
      AND rest.status = 1
      AND r.status = 1
) AS has_permission;
