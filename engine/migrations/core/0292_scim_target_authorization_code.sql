-- signari:compatible-with-previous
--
-- 0292_scim_target_authorization_code.sql
--
-- A SCIM target that takes the authorization code grant (7.14): somebody signs in at
-- the target once, and the refresh token that leaves is how each pass asks for an
-- access token. The refresh token is sealed under the root key as the client secret
-- is, and replaced whenever the token endpoint issues another. An authorization
-- somebody has started waits ten minutes with its PKCE verifier sealed and its state
-- kept only as a hash. Compatible with the previous release, which ignores these
-- columns and asks such a target's token endpoint for a client credentials grant as
-- the same client with the same secret: refused there or not, nothing is sent
-- anywhere it was not sent before.

-- Where somebody signs in, from the client the token URL is asked as. Each "a <= b"
-- below is "a implies b" read backwards: false sorts before true, so no authorization
-- URL means no token URL is required, and one means a token URL is.
ALTER TABLE core.scim_targets
    ADD COLUMN oauth_authorize_url text
        CHECK (oauth_authorize_url LIKE 'https://%' AND (oauth_token_url IS NULL) <= (oauth_authorize_url IS NULL));

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_refresh_token bytea;

-- A refresh token is held only with the time it was given, and only by a target that
-- takes the grant it belongs to.
ALTER TABLE core.scim_targets
    ADD COLUMN oauth_authorized_at timestamptz
        CHECK ((oauth_refresh_token IS NULL) = (oauth_authorized_at IS NULL)
               AND (oauth_authorize_url IS NULL) <= (oauth_refresh_token IS NULL));

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_pending_state bytea;

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_pending_verifier bytea;

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_pending_redirect text;

-- An authorization waiting for its code is all four or none.
ALTER TABLE core.scim_targets
    ADD COLUMN oauth_pending_until timestamptz
        CHECK ((oauth_pending_state IS NULL) = (oauth_pending_verifier IS NULL)
               AND (oauth_pending_state IS NULL) = (oauth_pending_redirect IS NULL)
               AND (oauth_pending_state IS NULL) = (oauth_pending_until IS NULL)
               AND (oauth_authorize_url IS NULL) <= (oauth_pending_state IS NULL));

COMMENT ON COLUMN core.scim_targets.oauth_authorize_url IS
    'where somebody signs in at the target for the authorization code grant; NULL for any other';
COMMENT ON COLUMN core.scim_targets.oauth_refresh_token IS
    'the refresh token that grant left, sealed under the root key (scim_refresh_token)';
COMMENT ON COLUMN core.scim_targets.oauth_pending_state IS
    'SHA-256 of the state an authorization was started with, spent by its code';
COMMENT ON COLUMN core.scim_targets.oauth_pending_verifier IS
    'that authorization''s PKCE verifier, sealed under the root key (scim_pkce_verifier)';
