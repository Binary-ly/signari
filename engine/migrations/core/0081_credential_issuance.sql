-- OID4VCI Credential Issuer: the half we did not implement.
--
-- Migration 0077 made Signari the AUTHORIZATION SERVER for OID4VCI -- it issues
-- the access token a credential endpoint would accept. This makes it the
-- CREDENTIAL ISSUER as well: it now mints the credential.
--
-- # Why a configuration table rather than code
--
-- §12.2 has the issuer publish `credential_configurations_supported`, a map from
-- an identifier a wallet requests to a description of what it gets. The contents
-- are a deployment's own business -- which claims a credential carries, which of
-- them are selectively disclosable -- so they are data, not Go.
CREATE TABLE core.credential_configurations (
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The key in `credential_configurations_supported`, and the value a wallet
    -- sends as `credential_configuration_id`.
    config_id   text NOT NULL,

    -- The credential format. Only SD-JWT VC is implemented, and the column
    -- exists so that adding mdoc later is a migration rather than a rewrite.
    format      text NOT NULL DEFAULT 'dc+sd-jwt'
                CHECK (format IN ('dc+sd-jwt')),

    -- draft-ietf-oauth-sd-jwt-vc-18 §3.2.2.1: the `vct` claim, "a
    -- Collision-Resistant Name", identifying what kind of credential this is.
    vct         text NOT NULL,

    -- Which user attributes become claims, and which of those are selectively
    -- disclosable.
    --
    -- Split rather than a single list with flags, because the distinction is the
    -- entire point of the format: a claim in `always` is visible to every
    -- verifier the holder ever presents to, and one in `selective` is visible
    -- only when the holder chooses. Putting them in one column with a boolean
    -- makes the more dangerous option the easier typo.
    always_claims    text[] NOT NULL DEFAULT '{}',
    selective_claims text[] NOT NULL DEFAULT '{}',

    -- How long an issued credential is valid. NULL means no `exp`, which is a
    -- deliberate choice for credentials whose validity is checked by status
    -- rather than by expiry.
    lifetime    interval,

    display_name text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (org_id, config_id),

    -- A configuration that carries nothing is one that issues an empty
    -- credential, which is never what anybody meant.
    CONSTRAINT credential_configurations_have_claims
        CHECK (cardinality(always_claims) + cardinality(selective_claims) > 0)
);

-- c_nonce values handed out by the Nonce Endpoint (§7).
--
-- Stored rather than derived, because §7.2 requires them to be unpredictable and
-- §8.2 requires the issuer to detect a stale one. A nonce that is merely a
-- signed timestamp cannot be invalidated after use, so replay is bounded by the
-- clock instead of by the issuer.
CREATE TABLE core.credential_nonces (
    nonce_hash  bytea PRIMARY KEY,
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_nonces_expiry_idx ON core.credential_nonces (expires_at);

COMMENT ON TABLE core.credential_configurations IS
    'OID4VCI 12.2 credential_configurations_supported. Which claims a credential carries, and which are selectively disclosable.';
