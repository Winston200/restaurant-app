-- Seed RBAC baseline data (idempotent via business unique codes / username).
-- Note: there is no admin_has_roles table; admin↔ role ↔ restaurant
-- is modeled by restaurant_admins (restaurant_id, admin_id, role_id).

-- 1) permissions
INSERT INTO permissions (name, code)
SELECT v.name, v.code
FROM (
    VALUES
        ('Super Admin Access', 'superadmin.access'),
        ('Restaurant Admin Access', 'restaurantadmin.access'),
        ('Order Manage', 'order.manage'),
        ('Category Manage', 'category.manage'),
        ('Table Manage', 'table.manage')
) AS v(name, code)
WHERE NOT EXISTS (
    SELECT 1 FROM permissions p WHERE p.code = v.code
);

-- 2) roles
INSERT INTO roles (name, code, status)
SELECT v.name, v.code, 1
FROM (
    VALUES
        ('Super Admin', 'superadmin'),
        ('Restaurant Admin', 'restaurantadmin')
) AS v(name, code)
WHERE NOT EXISTS (
    SELECT 1 FROM roles r WHERE r.code = v.code
);

-- 3) role_has_permissions: superadmin → all 5
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'superadmin'
  AND p.code IN (
      'superadmin.access',
      'restaurantadmin.access',
      'order.manage',
      'category.manage',
      'table.manage'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM role_has_permissions rhp
      WHERE rhp.role_id = r.id
        AND rhp.permission_id = p.id
  );

-- 3b) role_has_permissions: restaurantadmin → 4 (no superadmin.access)
INSERT INTO role_has_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
CROSS JOIN permissions p
WHERE r.code = 'restaurantadmin'
  AND p.code IN (
      'restaurantadmin.access',
      'order.manage',
      'category.manage',
      'table.manage'
  )
  AND NOT EXISTS (
      SELECT 1
      FROM role_has_permissions rhp
      WHERE rhp.role_id = r.id
        AND rhp.permission_id = p.id
  );

-- 4) test restaurant
INSERT INTO restaurants (name, code, status)
SELECT 'Test Restaurant', 'TEST001', 1
WHERE NOT EXISTS (
    SELECT 1 FROM restaurants WHERE code = 'TEST001'
);

-- 5) test super admin account
-- password: 123456 (bcrypt via golang.org/x/crypto/bcrypt, DefaultCost)
INSERT INTO admins (username, password_hash, name, status)
SELECT
    'admin',
    '$2a$10$vsyf/99.wKuLM7HLalpsMe03Y3ymOHGsCyb8FiVCIBX5.h6sYODGW',
    'Admin',
    1
WHERE NOT EXISTS (
    SELECT 1 FROM admins WHERE LOWER(username) = LOWER('admin')
);

-- 6) link admin ↔ TEST001 ↔ superadmin via restaurant_admins
--    (replaces the non-existent admin_has_roles table)
INSERT INTO restaurant_admins (restaurant_id, admin_id, role_id)
SELECT rest.id, a.id, r.id
FROM restaurants rest
CROSS JOIN admins a
CROSS JOIN roles r
WHERE rest.code = 'TEST001'
  AND LOWER(a.username) = LOWER('admin')
  AND r.code = 'superadmin'
  AND NOT EXISTS (
      SELECT 1
      FROM restaurant_admins ra
      WHERE ra.restaurant_id = rest.id
        AND ra.admin_id = a.id
        AND ra.role_id = r.id
  );
