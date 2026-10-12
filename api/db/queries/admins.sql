-- name: GetAdminByLogin :one
SELECT
    id,
    username,
    password_hash,
    name,
    phone,
    status,
    last_login_at,
    created_at,
    updated_at
FROM admins
WHERE LOWER(username) = LOWER(sqlc.arg(login))
   OR (phone IS NOT NULL AND phone = sqlc.arg(login))
LIMIT 1;

-- name: GetAdminByID :one
SELECT
    id,
    username,
    password_hash,
    name,
    phone,
    status,
    last_login_at,
    created_at,
    updated_at
FROM admins
WHERE id = $1
LIMIT 1;

-- name: ListAdminRestaurantRoles :many
SELECT
    ra.restaurant_id,
    rest.code AS restaurant_code,
    rest.name AS restaurant_name,
    ra.role_id,
    r.code AS role_code,
    r.name AS role_name
FROM restaurant_admins ra
INNER JOIN restaurants rest ON rest.id = ra.restaurant_id
INNER JOIN roles r ON r.id = ra.role_id
WHERE ra.admin_id = $1
  AND rest.status = 1
  AND r.status = 1
ORDER BY rest.code ASC, r.code ASC;
