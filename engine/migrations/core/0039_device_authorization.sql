-- The device authorization grant, RFC 8628.
--
-- For inputs that cannot host a browser: a TV, a CLI, a headless box. The device
-- shows a short code, the person types it on a device that does have a browser,
-- and the device polls until they approve.
--
-- # The attack this table is shaped around
--
-- Device code phishing. An attacker starts the flow on their own device, gets a
-- user code, and sends it to a victim with a plausible story. The victim types
-- it into the REAL identity provider, sees a real consent screen, approves --
-- and the attacker's device receives the tokens. Nothing in the protocol is
-- violated; the victim authorised the wrong device.
--
-- Nothing here can fully prevent that, so the design narrows it:
--
--   * short expiry (10 minutes, not the hours some implementations allow)
--   * the approval screen names the client and says a DEVICE is being authorised
--   * the user code is single-use and dies on first approval or denial
--   * the verification endpoint is rate limited (RFC 8628 §5.1)
--
-- A per-record attempt counter was drafted here and removed: when somebody types
-- a wrong code there is no record to count it against, because we cannot know
-- which one they were aiming at. It would have been a column nothing increments,
-- which is the exact defect this project keeps finding in itself. The rate limit
-- is the mechanism that actually works.
--
-- # Two codes, two purposes
--
-- device_code is long, random and secret: it authenticates the polling device.
-- user_code is short enough to type, so it is low entropy by necessity -- which
-- is exactly why it is rate limited, single use and short lived. Both are stored
-- as hashes: this table would otherwise be a list of live credentials.

SET search_path = core, public;

CREATE TABLE core.device_authorizations (
    id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id           uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    client_id        text NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,

    -- SHA-256 of each code. Never the codes themselves.
    device_code_hash bytea NOT NULL UNIQUE CHECK (length(device_code_hash) = 32),
    user_code_hash   bytea NOT NULL UNIQUE CHECK (length(user_code_hash) = 32),

    scope            text NOT NULL DEFAULT '',
    -- RFC 8707, carried through so a device grant can be audience-restricted
    -- like every other grant here.
    resource         text[] NOT NULL DEFAULT '{}',

    -- pending -> approved | denied. Never back.
    status           text NOT NULL DEFAULT 'pending'
                     CHECK (status IN ('pending','approved','denied')),

    -- Set when a person approves. The grant is issued as THEM.
    user_id          uuid REFERENCES core.users(id) ON DELETE CASCADE,
    sid              text,

    -- Polling discipline (RFC 8628 §3.5). last_polled_at is what makes
    -- slow_down truthful rather than advisory.
    interval_s       int NOT NULL DEFAULT 5,
    last_polled_at   timestamptz,

    -- Single use: set once the device has collected its tokens, so a replayed
    -- device_code gets nothing.
    redeemed_at      timestamptz,

    expires_at       timestamptz NOT NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),

    -- An approved record must say who approved it. Without this a bug that
    -- approves without setting user_id would mint a token belonging to nobody.
    CONSTRAINT device_auth_approved_has_user
        CHECK (status <> 'approved' OR user_id IS NOT NULL)
);

CREATE INDEX device_auth_user_code_idx ON core.device_authorizations (user_code_hash)
    WHERE status = 'pending';
CREATE INDEX device_auth_expiry_idx ON core.device_authorizations (expires_at);

ALTER TABLE core.device_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.device_authorizations FORCE ROW LEVEL SECURITY;

CREATE POLICY device_authorizations_org_isolation ON core.device_authorizations
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.device_authorizations IS
    'RFC 8628 device authorization grant. Both codes stored as SHA-256. Short '
    'expiry and a rate-limited verification endpoint narrow device code phishing, '
    'which the protocol cannot prevent outright.';
