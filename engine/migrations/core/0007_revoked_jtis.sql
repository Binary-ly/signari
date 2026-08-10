-- 0007_revoked_jtis.sql
--
-- Makes RFC 7009 revocation of an ACCESS token mean something.
--
-- Refresh tokens are already revocable: they are stored, so revoking one kills
-- its family and the next refresh fails. Access tokens here are signed JWTs and
-- are therefore, by construction, valid until they expire. The usual response is
-- to return 200 from /revoke and do nothing -- the spec even permits it (RFC 7009
-- §2.1). That is a lie an operator only discovers during an incident, which is
-- precisely when they are relying on it.
--
-- So: a denylist of jti, checked wherever WE are the resource server (userinfo,
-- introspection). It is honest rather than complete, and the boundary is worth
-- stating plainly:
--
--   * Anything that asks us -- introspection, userinfo -- sees the revocation
--     immediately.
--   * A resource server validating the JWT locally, offline, will keep accepting
--     the token until it expires. No issuer can change that without making the
--     token stateful; it is the trade JWTs make. Access token TTL is 5 minutes,
--     which is the real bound on that exposure, and RFC 7662 introspection is the
--     answer for resource servers that cannot accept it.
--
-- Rows are deleted by the janitor once expires_at has passed: after that the
-- token is rejected on its own expiry and the row proves nothing.

SET search_path = core, public;

CREATE TABLE revoked_jtis (
    -- The jti claim of the revoked access token, not a hash of the token: the
    -- jti is already an opaque random value we minted, and storing the token
    -- itself would put a live credential in a table whose whole purpose is to
    -- be read on every request.
    jti        text        PRIMARY KEY,

    -- Which client revoked it. A client may only revoke its OWN tokens, and this
    -- records who did so for the audit trail.
    client_id  text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- The token's own expiry, so the row can be dropped once it is moot.
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz NOT NULL DEFAULT now()
);

-- The janitor deletes by expiry; introspection and userinfo look up by primary
-- key, which needs no further index.
CREATE INDEX revoked_jtis_expiry_idx ON revoked_jtis (expires_at);

-- Not tenant-scoped by RLS: a jti is an opaque random string that identifies
-- nothing on its own, and the lookup happens on the request path before any org
-- context exists. Guessing one to learn "this token was revoked" reveals nothing
-- a caller could not learn by simply presenting the token.
ALTER TABLE revoked_jtis ENABLE ROW LEVEL SECURITY;
ALTER TABLE revoked_jtis FORCE ROW LEVEL SECURITY;

-- Explicit and permissive rather than simply leaving RLS off: with RLS enabled
-- the default is "no policy means no access", so the exception has to be written
-- down and reviewed rather than inferred from a missing line.
CREATE POLICY revoked_jtis_all ON revoked_jtis
    USING (true) WITH CHECK (true);
