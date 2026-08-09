-- 0004_session_cookie_split.sql
--
-- Separates the session's PUBLIC identifier from its SECRET bearer token.
--
-- The bug this fixes, found by running the end-to-end flow: the session cookie
-- value was being used directly as `sid`, and `sid` is published in every ID
-- token and every back-channel logout token. Any relying party holding an ID
-- token could have set that cookie and assumed the session.
--
-- Two values, two jobs:
--
--   sid          public. Goes in ID tokens and logout tokens. Identifies a
--                session so an RP can be told which one ended. Not a credential.
--   cookie_hash  secret. SHA-256 of the value in the browser's cookie. Only the
--                hash is stored, for the same reason authorization codes are
--                stored hashed: a database read must not yield a live session.
--
-- Knowing a sid must grant nothing. That is what makes it safe to publish.

SET search_path = core, public;

ALTER TABLE core.sessions ADD COLUMN cookie_hash bytea;

-- Existing rows have no separate cookie value, so they cannot be authenticated
-- under the new scheme. Ending them is the honest migration: a session whose
-- credential is indistinguishable from its public id should not survive.
UPDATE core.sessions
SET revoked_at = now(), revocation_reason = 'admin_revoke'
WHERE revoked_at IS NULL AND cookie_hash IS NULL;

-- Enforced from here on. Partial index so revoked rows may keep a NULL.
CREATE UNIQUE INDEX sessions_cookie_hash_key
    ON core.sessions (cookie_hash) WHERE cookie_hash IS NOT NULL;

COMMENT ON COLUMN core.sessions.sid IS
    'Public session identifier. Published in ID tokens and logout tokens. Grants nothing.';
COMMENT ON COLUMN core.sessions.cookie_hash IS
    'SHA-256 of the session cookie value. The secret half; never published.';
