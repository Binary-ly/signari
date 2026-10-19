-- 0141_webauthn_spent_challenges.sql
--
-- A WebAuthn challenge is spent by the first attempt to finish its ceremony.
--
-- # The defect
--
-- The challenge travels in a signed cookie, which makes it bound to the
-- browser and unforgeable, and the finish handler clears that cookie. Clearing
-- is a request to the browser, not a fact on the server: the same cookie and
-- the same assertion, presented again, verified again and opened a second
-- session. The signature counter did not stop it either. A repeated count is
-- recorded and, unless the operator refuses cloned authenticators, signed in
-- anyway, and synced passkeys report a counter of zero on every assertion.
--
-- So a sign-in captured from a proxy log or a debugging tool was a second
-- session for whoever held it, for the five minutes the ceremony lives.
--
-- # The record
--
-- The challenge's hash, kept until a while past the ceremony's own expiry,
-- after which the cookie is refused as expired before this table is consulted.
-- Written on every attempt to finish, successful or not, because a challenge
-- that survives a failed attempt can be ground against.

SET search_path = core, public;

CREATE TABLE webauthn_spent_challenges (
    -- SHA-256 of the challenge. The challenge is 32 random bytes the server
    -- chose, so it is unique without a tenant in the key, and a tenant in the
    -- key would let the same ceremony be spent once per organisation.
    challenge_hash bytea       PRIMARY KEY,
    spent_at       timestamptz NOT NULL DEFAULT now(),
    -- Swept by the janitor.
    expires_at     timestamptz NOT NULL
);

CREATE INDEX webauthn_spent_challenges_expiry_idx ON webauthn_spent_challenges (expires_at);

-- No RLS, for the reason dpop_seen_jtis has none: no tenant data and no
-- identity, only opaque values whose purpose is to have been seen.
GRANT SELECT ON webauthn_spent_challenges TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER webauthn_spent_challenges_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.webauthn_spent_challenges
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
