SET search_path = core, public;

-- A provider that only ever SIGNS assertions, and is never signed in through.
--
-- # Why the existing kinds could not express this
--
-- `idp add` discovers a generic OIDC provider's endpoints and refuses one whose
-- discovery document names no authorization or token endpoint. That is right for
-- interactive sign-in and it makes the most important class of RFC 7523 issuer
-- unregisterable, because those issuers have no such endpoints and never will:
--
--   $ signari idp add -kind oidc -issuer https://token.actions.githubusercontent.com
--   signari: discovering ...: the discovery document names no authorization or
--            token endpoint
--
-- GitHub Actions, Kubernetes service-account issuers and SPIFFE bundles publish a
-- JWKS and nothing else. There is nothing to redirect a browser to, and nothing
-- to exchange a code at. They are key publishers, not login providers.
--
-- `saml` already sets the precedent: it takes its own registration path because
-- it "has no client ID, no scopes and no discovery document". An assertion issuer
-- has less than that again.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind = ANY (ARRAY['oidc', 'google', 'github', 'microsoft', 'saml',
                             'apple', 'gitlab', 'discord', 'twitch', 'linkedin',
                             'slack', 'atlassian', 'assertion']));

-- Same exemption SAML has, for the same reason: there is no client registration
-- at an assertion issuer, so there is no client id to hold.
ALTER TABLE identity_providers DROP CONSTRAINT identity_providers_client_id_present;
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_client_id_present
    CHECK (kind IN ('saml', 'assertion') OR client_id <> '');

-- An assertion issuer is USELESS without both of these, and the failure without
-- them is silent: every assertion is refused as "issuer not trusted" or "cannot
-- be verified", which reads as a configuration mistake somewhere else entirely.
-- The database refuses the row instead.
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_assertion_needs_keys
    CHECK (kind <> 'assertion'
           OR (issuer IS NOT NULL AND issuer <> ''
               AND jwks_url IS NOT NULL AND jwks_url <> ''));

-- And it must never appear as an interactive sign-in option. There is no
-- authorize endpoint to send a browser to, so /login/with/<slug> would produce a
-- redirect to nowhere -- a broken login button created as a side effect of
-- configuring a machine-to-machine trust.
--
-- Enforced in the schema rather than only in the handler, because the sign-in
-- path reads this table from several places and a rule held in one of them is a
-- rule that holds until somebody adds the next one.
ALTER TABLE identity_providers ADD CONSTRAINT identity_providers_assertion_not_interactive
    CHECK (kind <> 'assertion' OR (allow_signup = false AND allow_linking = false));

COMMENT ON COLUMN identity_providers.kind IS
    'Provider family. `oidc` and the named brands are interactive sign-in; `saml` '
    'is an upstream SAML IdP; `assertion` only publishes keys for RFC 7523 '
    'jwt-bearer and is never signed in through.';
