-- 0284_oid4vp_verifier.sql
--
-- Signing in with a credential from a wallet (12.12): an identity provider of kind oid4vp is
-- this deployment acting as an OpenID4VP verifier. It asks a wallet for one SD-JWT VC of the
-- types it names, believes the issuers it lists with the keys pinned for each, and signs in
-- the person a claim of that credential identifies, read together with the issuer, because a
-- claim is unique only within the issuer that made it (OID4VP 1.0 §14.4).

ALTER TABLE core.identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE core.identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind = ANY (ARRAY['oidc', 'oauth2', 'google', 'github', 'microsoft', 'saml',
                             'apple', 'gitlab', 'discord', 'twitch', 'linkedin',
                             'slack', 'atlassian', 'assertion', 'oid4vp']));
-- A verifier is the client here: it has no client id issued to it by anybody.
ALTER TABLE core.identity_providers DROP CONSTRAINT identity_providers_client_id_present;
ALTER TABLE core.identity_providers ADD CONSTRAINT identity_providers_client_id_present
    CHECK (kind IN ('saml', 'assertion', 'oid4vp') OR client_id <> '');

CREATE TABLE core.vp_verifiers (
    provider_id      uuid        PRIMARY KEY REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    org_id           uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- How the wallet is told who is asking. Both x509 prefixes sign the request with the key of
    -- the certificate chain held here; redirect_uri cannot sign at all.
    client_id_prefix text        NOT NULL
                                 CHECK (client_id_prefix IN ('x509_san_dns', 'x509_hash', 'redirect_uri')),
    -- Where the browser is sent with the request: a wallet's universal link, or openid4vp://.
    wallet_url       text        NOT NULL DEFAULT 'openid4vp://',
    vct_values       text[]      NOT NULL CHECK (cardinality(vct_values) > 0),
    -- Claim paths, as JSON arrays: the one that identifies the person, and where the address
    -- and the name are. Each is asked for, and a credential without it is refused.
    subject_claim    text        NOT NULL CHECK (subject_claim <> ''),
    email_claim      text        NOT NULL DEFAULT '',
    name_claim       text        NOT NULL DEFAULT '',
    signing_key      bytea,
    certificate_chain text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT vp_verifiers_signed_prefix CHECK (client_id_prefix = 'redirect_uri'
        OR (signing_key IS NOT NULL AND certificate_chain IS NOT NULL))
);

CREATE INDEX vp_verifiers_org ON core.vp_verifiers (org_id);

ALTER TABLE core.vp_verifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.vp_verifiers FORCE ROW LEVEL SECURITY;
CREATE POLICY vp_verifiers_org_isolation ON core.vp_verifiers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.vp_verifiers TO signari_maintenance;

CREATE TRIGGER vp_verifiers_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.vp_verifiers
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- The issuers a verifier believes, each with the keys its credentials are checked with. An
-- issuer not listed is not believed, whatever it signed with.
CREATE TABLE core.vp_trusted_issuers (
    provider_id uuid        NOT NULL REFERENCES core.vp_verifiers(provider_id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    issuer      text        NOT NULL CHECK (issuer <> ''),
    jwks        jsonb       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider_id, issuer)
);

CREATE INDEX vp_trusted_issuers_org ON core.vp_trusted_issuers (org_id);

ALTER TABLE core.vp_trusted_issuers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.vp_trusted_issuers FORCE ROW LEVEL SECURITY;
CREATE POLICY vp_trusted_issuers_org_isolation ON core.vp_trusted_issuers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.vp_trusted_issuers TO signari_maintenance;

CREATE TRIGGER vp_trusted_issuers_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.vp_trusted_issuers
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- A presentation, between the wallet posting it and the browser coming back for it: what it
-- proved, sealed under the root key because it is about a person, and the hash of the code the
-- browser has to bring. Both go with the pending sign-in, which is deleted when it is used.
ALTER TABLE core.federated_logins ADD COLUMN vp_presented bytea;
ALTER TABLE core.federated_logins ADD COLUMN vp_response_code_hash bytea;
