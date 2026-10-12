-- name: GetAdminByUsername :one
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
WHERE LOWER(username) = LOWER(sqlc.arg(username))
LIMIT 1;

-- name: GetRestaurantByCode :one
SELECT
    id,
    name,
    code,
    logo,
    phone,
    address,
    description,
    status,
    created_at,
    updated_at
FROM restaurants
WHERE code = $1
LIMIT 1;

-- name: ListPermissionsByRoleCode :many
SELECT
    p.id,
    p.name,
    p.code,
    p.description,
    p.created_at,
    p.updated_at
FROM permissions p
INNER JOIN role_has_permissions rhp ON rhp.permission_id = p.id
INNER JOIN roles r ON r.id = rhp.role_id
WHERE r.code = $1
ORDER BY p.code;
