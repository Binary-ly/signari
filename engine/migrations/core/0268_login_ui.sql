-- signari:compatible-with-previous
-- 0268_login_ui.sql
--
-- The page a client draws its own sign-in on (10.11). Set, an authorization request that needs
-- a sign-in is sent there rather than to this server's page, and the application walks the same
-- stages over JSON. A client that names none cannot be signed in that way, because a page of an
-- application's own is one more place a password is typed.

ALTER TABLE core.clients ADD COLUMN login_ui_url text
    CHECK (login_ui_url IS NULL OR login_ui_url ~ '^https://[^#]+$'
           OR login_ui_url ~ '^http://(localhost|127\.0\.0\.1)(:[0-9]+)?(/[^#]*)?$');
