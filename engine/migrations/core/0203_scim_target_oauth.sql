-- signari:compatible-with-previous
--
-- 0203_scim_target_oauth.sql
--
-- A SCIM target that takes a client credentials grant rather than a long-lived
-- bearer token (7.14). The client secret is held where the token is, in the sealed
-- token column, so nothing new has to be sealed, rotated or kept out of an export.
--
-- A token URL and a client come together: one with no other has nobody to ask as,
-- or nowhere to ask, and is what a half-finished registration looks like.

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_token_url text CHECK (oauth_token_url LIKE 'https://%');

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_client_id text
        CHECK ((oauth_token_url IS NULL) = (oauth_client_id IS NULL) AND oauth_client_id <> '');

-- No token URL means no scope: false sorts before true.
ALTER TABLE core.scim_targets
    ADD COLUMN oauth_scope text CHECK ((oauth_token_url IS NULL) <= (oauth_scope IS NULL));
