-- name: CreateAdminRefreshSession :one
INSERT INTO admin_refresh_sessions (
    admin_id,
    token_hash,
    expires_at
) VALUES (
    $1, $2, $3
) RETURNING
    id,
    admin_id,
    token_hash,
    expires_at,
    revoked_at,
    replaced_by_hash,
    created_at,
    updated_at;

-- name: GetAdminRefreshSessionByHash :one
SELECT
    id,
    admin_id,
    token_hash,
    expires_at,
    revoked_at,
    replaced_by_hash,
    created_at,
    updated_at
FROM admin_refresh_sessions
WHERE token_hash = $1
LIMIT 1;

-- name: RevokeAdminRefreshSession :exec
UPDATE admin_refresh_sessions
SET
    revoked_at = NOW(),
    updated_at = NOW()
WHERE id = $1
  AND revoked_at IS NULL;

-- name: RotateAdminRefreshSession :exec
UPDATE admin_refresh_sessions
SET
    revoked_at = NOW(),
    replaced_by_hash = $2,
    updated_at = NOW()
WHERE id = $1
  AND revoked_at IS NULL;

-- name: RevokeAllAdminRefreshSessions :exec
UPDATE admin_refresh_sessions
SET
    revoked_at = NOW(),
    updated_at = NOW()
WHERE admin_id = $1
  AND revoked_at IS NULL;
