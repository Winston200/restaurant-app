ALTER TABLE restaurant_admins
    DROP CONSTRAINT restaurant_admins_restaurant_id_admin_id_key;

ALTER TABLE restaurant_admins
    ADD CONSTRAINT restaurant_admins_restaurant_id_admin_id_role_id_key
    UNIQUE (restaurant_id, admin_id, role_id);
