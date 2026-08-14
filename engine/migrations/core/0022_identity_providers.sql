
SET search_path = core, public;

CREATE TABLE identity_providers (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Short name used in URLs: /login/with/<slug>.
    slug          text        NOT NULL,
    display_name  text        NOT NULL,
    -- `oidc` is the generic case; the named ones only preset endpoints and the
    -- quirks each provider has around email verification.
    kind          text        NOT NULL DEFAULT 'oidc'
                              CHECK (kind IN ('oidc','google','github','microsoft')),

    client_id     text        NOT NULL,
    -- Sealed with the root key, never stored in the clear. An identity
    -- provider's own database is a high-value target precisely because it holds
    -- credentials for other systems.
    client_secret bytea,

    -- Discovery URL for `oidc`; the named kinds fill these in themselves.
    issuer            text,
    authorize_url     text,
    token_url         text,
    userinfo_url      text,
    jwks_url          text,
    scopes            text[]  NOT NULL DEFAULT ARRAY['openid','email','profile'],

    -- # The two policy switches, and what is deliberately NOT here
    --
    -- allow_signup: an unknown external subject may create a new local user.
    -- allow_linking: an external account may be attached to an existing local
    --   user -- and that ALWAYS requires the user to sign in locally first.
    --
    -- There is no third switch for "match on email". It is not configurable
    -- because there is no setting of it that is safe, and an option that can be
    -- turned on is an option that will be found turned on.
    allow_signup  boolean     NOT NULL DEFAULT true,
    allow_linking boolean     NOT NULL DEFAULT true,

    -- Whether to insist the provider marks the address verified before we
    -- record it. On by default. GitHub in particular will hand back an
    -- unverified address unless you ask it not to.
    require_verified_email boolean NOT NULL DEFAULT true,

    enabled       boolean     NOT NULL DEFAULT true,
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, slug)
);

-- The link between a local user and an external account.
CREATE TABLE federated_identities (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id  uuid        NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The external provider's stable identifier for this person. THE key this
    -- table is looked up by, and the only one.
    subject      text        NOT NULL,

    -- Recorded for display and support, never for matching. Kept explicitly
    -- separate from `users.email` so that nothing is tempted to join on it.
    email        text,
    email_verified boolean   NOT NULL DEFAULT false,

    linked_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,

    -- One external account maps to at most one local user. Without this, two
    -- local accounts could claim the same external identity and which one you
    -- got would depend on row order.
    UNIQUE (provider_id, subject),
    -- And one local user has at most one account per provider, so "sign in with
    -- Google" is unambiguous.
    UNIQUE (provider_id, user_id)
);

CREATE INDEX federated_identities_user_idx ON federated_identities (user_id);

-- In-flight external logins.
--
-- state, nonce and the PKCE verifier for a flow we started. Held server-side
-- and bound to the browser by a cookie, so a callback cannot be replayed into
-- a different browser -- which is the login-CSRF shape of this flow.
CREATE TABLE federated_logins (
    state_hash   bytea       PRIMARY KEY,
    provider_id  uuid        NOT NULL REFERENCES identity_providers(id) ON DELETE CASCADE,
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    nonce        text        NOT NULL,
    code_verifier text       NOT NULL,
    -- Hash of a value in a cookie set at the same moment. The callback must
    -- present both, which is what binds the flow to one browser.
    binding_hash bytea       NOT NULL,
    -- Set when the flow was started by a signed-in user to LINK an account
    -- rather than to sign in. Carrying it here means the callback cannot be
    -- talked into linking by adding a parameter.
    link_user_id uuid        REFERENCES users(id) ON DELETE CASCADE,
    -- Where to go afterwards. Validated when the flow starts.
    return_to    text,
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '10 minutes'
);

CREATE INDEX federated_logins_expiry_idx ON federated_logins (expires_at);

DO $$
DECLARE
    t text;
    tenant_tables text[] := ARRAY[
        'identity_providers','federated_identities','federated_logins'
    ];
BEGIN
    FOREACH t IN ARRAY tenant_tables LOOP
        EXECUTE format('ALTER TABLE core.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('ALTER TABLE core.%I FORCE ROW LEVEL SECURITY', t);
        EXECUTE format($f$
            CREATE POLICY %I_org_isolation ON core.%I
            USING (core.is_engine() OR org_id = core.current_org_id())
            WITH CHECK (core.is_engine() OR org_id = core.current_org_id())
        $f$, t, t);
    END LOOP;
END
$$;

GRANT SELECT ON identity_providers, federated_identities, federated_logins
    TO signari_maintenance;
