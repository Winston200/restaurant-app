-- Rollback only the seed data created by 000009 (identified by business codes).
-- Delete order respects foreign keys.

-- 1) remove restaurant_admins link for seeded admin + restaurant + role
DELETE FROM restaurant_admins ra
USING restaurants rest, admins a, roles r
WHERE ra.restaurant_id = rest.id
  AND ra.admin_id = a.id
  AND ra.role_id = r.id
  AND rest.code = 'TEST001'
  AND LOWER(a.username) = LOWER('admin')
  AND r.code = 'superadmin';

-- 2) remove role_has_permissions for seeded roles ↔ seeded permissions
DELETE FROM role_has_permissions rhp
USING roles r, permissions p
WHERE rhp.role_id = r.id
  AND rhp.permission_id = p.id
  AND r.code IN ('superadmin', 'restaurantadmin')
  AND p.code IN (
      'superadmin.access',
      'restaurantadmin.access',
      'order.manage',
      'category.manage',
      'table.manage'
  );

-- 3) remove seeded admin
DELETE FROM admins
WHERE LOWER(username) = LOWER('admin');

-- 4) remove seeded restaurant
DELETE FROM restaurants
WHERE code = 'TEST001';

-- 5) remove seeded roles
DELETE FROM roles
WHERE code IN ('superadmin', 'restaurantadmin');

-- 6) remove seeded permissions
DELETE FROM permissions
WHERE code IN (
    'superadmin.access',
    'restaurantadmin.access',
    'order.manage',
    'category.manage',
    'table.manage'
);
