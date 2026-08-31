-- Scopes an organisation defines, as objects rather than strings.
--
-- # What was wrong with strings
--
-- A scope existed because somebody typed the same word into two places: the
-- client's registered `scopes` array, and a claim mapper's `required_scope`.
-- Nothing connected them, so a typo in either was silent and fail-closed in the
-- worst way — the mapper waits for a scope no client can ever be granted, the
-- claim is simply never released, and the operator sees a correct-looking
-- configuration producing no claim.
--
-- Declaring the scope gives both ends something to point at, lets the consent
-- screen say what the client is actually asking for, and lets discovery
-- advertise it so an integrator can find it without being told.
--
-- # What this does NOT change
--
-- A client still cannot request a scope it is not registered for -- that check
-- is `Client.UnknownScopes`, enforced at /authorize, the device and CIBA
-- endpoints, jwt-bearer and client_credentials. This catalogue is about what
-- may be REGISTERED and how it is DESCRIBED, not a new gate on the request. The
-- gate was already there and is not weakened by anything here.
--
-- # Why the standard scopes are not rows
--
-- `openid`, `profile`, `email`, `groups` and `offline_access` mean what the
-- specifications say they mean, and their behaviour is in code. A row that
-- appeared to redefine `email` would be a configuration surface over something
-- that is not configurable -- an operator could rename its description and
-- change nothing, which is the shape of a control that does not exist.

CREATE TABLE core.scopes (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The token as it appears in a scope string. RFC 6749 §3.3 gives the
    -- allowed characters as %x21 / %x23-5B / %x5D-7E, which excludes the space
    -- that separates them and the double quote and backslash. Narrowed further
    -- here to what can also appear in a URL and a configuration file without
    -- quoting, because a scope that needs escaping somewhere is one that will
    -- eventually not be escaped.
    name        text        NOT NULL
                            CHECK (name ~ '^[a-zA-Z][a-zA-Z0-9_:.-]{0,63}$'),

    display_name text       NOT NULL DEFAULT '',

    -- Shown on the consent screen. The whole reason a scope is worth declaring:
    -- "hr_records" tells a person nothing, and a consent screen that cannot
    -- explain what is being asked for is a consent screen that collects a click
    -- rather than a decision.
    description text        NOT NULL DEFAULT '',

    -- Whether the scope may be advertised in the discovery document.
    --
    -- Default true, but not always right: a scope used only between a first-party
    -- client and its own resource server is not something a stranger reading
    -- discovery needs to learn exists, and every advertised scope is a hint
    -- about what this deployment holds.
    advertise   boolean     NOT NULL DEFAULT true,

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, name)
);

-- The standard scopes are reserved. A row redefining one would be a
-- configuration surface over behaviour that lives in code.
ALTER TABLE core.scopes ADD CONSTRAINT scopes_not_a_standard_scope
    CHECK (name NOT IN ('openid','profile','email','address','phone',
                        'groups','offline_access'));

ALTER TABLE core.scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.scopes FORCE ROW LEVEL SECURITY;
CREATE POLICY scopes_org_isolation ON core.scopes
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
