-- Post-M8 item 16: drop the dead vault_items table.
--
-- vault_items was created for "connector credentials and other secrets"
-- but never gained a consumer: no code path reads or writes it, and the
-- app role was denied entirely (0002: USING (false)). A credentials-shaped
-- table that nothing uses is worse than no table — it invites future code
-- to assume a working secrets store exists. If connector credentials ever
-- need a home, they get a designed, tested table then, not this one.
DROP TABLE IF EXISTS vault_items;
