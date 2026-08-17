-- Previous passwords, so one cannot be reused.
--
-- core.password_credentials holds one row per user, so there was nowhere to
-- keep the old ones. This is that place.
--
-- # Hashes, and only as many as the policy needs
--
-- These are Argon2id hashes, not passwords, and they are kept because there is
-- no other way to answer "is this the same as last time" -- comparing plaintext
-- would mean storing plaintext. The janitor trims each user to the configured
-- depth, so a deployment that checks the last three does not accumulate ten
-- years of hashes for a question nobody asks.
CREATE TABLE core.password_history (
    id         bigserial PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    org_id     uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    hash       text NOT NULL,
    algorithm  text NOT NULL,
    retired_at timestamptz NOT NULL DEFAULT now()
);

-- The lookup is always "this user's most recent N", so the index is ordered.
CREATE INDEX password_history_recent ON core.password_history (user_id, retired_at DESC);

ALTER TABLE core.password_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.password_history FORCE ROW LEVEL SECURITY;
-- The engine hatch, without which the engine reads nothing here and reuse is
-- silently permitted. See 0058, where this was forgotten once.
CREATE POLICY password_history_org_isolation ON core.password_history
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.password_history IS
    'Argon2id hashes of retired passwords, kept only to refuse reuse and trimmed '
    'by the janitor to the configured depth.';
