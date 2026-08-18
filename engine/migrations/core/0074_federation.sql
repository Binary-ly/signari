-- OpenID Federation 1.0 (Final, 17 February 2026): Entity Configuration.
--
-- # Why federation keys are separate from signing keys
--
-- Section 3.1.1, of the `jwks` claim in an Entity Statement:
--
--   "These Federation Entity Keys SHOULD NOT be used in other protocols. (Keys
--   to be used in other protocols, such as OpenID Connect, are conveyed in the
--   metadata elements for the protocol's Entity Type Identifiers, such as the
--   metadata under the openid_provider and openid_relying_party Entity Type
--   Identifiers.)"
--
-- The naive implementation reuses the OIDC signing key, because it is already
-- there and already published. That conflates two trust decisions: a relying
-- party trusts our OIDC key to assert who a user is, and a federation trusts our
-- federation key to assert what this entity IS and who vouches for it. Rotating
-- one should not rotate the other, and compromising one should not forge the
-- other.
--
-- So `purpose` is added to signing_keys rather than a separate table: the
-- rotation machinery, the wrapping, the state transitions and the retirement
-- sweep are all already correct here, and a second table would be a second copy
-- of them that eventually drifts.
ALTER TABLE core.signing_keys
    ADD COLUMN purpose text NOT NULL DEFAULT 'oidc';

ALTER TABLE core.signing_keys
    ADD CONSTRAINT signing_keys_purpose_check
    CHECK (purpose IN ('oidc', 'federation'));

-- Existing keys are OIDC keys. Stated explicitly rather than relying on the
-- default, so a restore from a dump taken before this migration lands correctly.
UPDATE core.signing_keys SET purpose = 'oidc' WHERE purpose IS NULL;

-- The JWKS query and the rotation query both filter on this now, so it is in
-- every index that mattered.
DROP INDEX IF EXISTS core.signing_keys_instance_state_idx;
CREATE INDEX signing_keys_instance_purpose_state_idx
    ON core.signing_keys (instance_id, purpose, state);

-- Federation configuration, one row per instance.
--
-- Separate from the instance row because most deployments never join a
-- federation, and a table of nulls on the hot path is worse than an outer join
-- on a cold one.
CREATE TABLE core.federation_config (
    instance_id uuid PRIMARY KEY REFERENCES core.instances(id) ON DELETE CASCADE,

    -- authority_hints: the Immediate Superiors of this entity.
    --
    -- Section 3.1.2: "This Claim is REQUIRED in Entity Configurations of the
    -- Entities that have at least one Superior above them... and MUST NOT be
    -- the empty array []. This Claim MUST NOT be present in Entity
    -- Configurations of Trust Anchors with no Superiors."
    --
    -- So an empty array and an absent value mean different things, and the
    -- column is nullable to keep them distinguishable. A CHECK enforces that a
    -- present value is non-empty, because `[]` is the one thing it may not be.
    authority_hints text[],
    CONSTRAINT federation_authority_hints_not_empty
        CHECK (authority_hints IS NULL OR cardinality(authority_hints) > 0),

    -- trust_anchor_hints, same rule.
    trust_anchor_hints text[],
    CONSTRAINT federation_trust_anchor_hints_not_empty
        CHECK (trust_anchor_hints IS NULL OR cardinality(trust_anchor_hints) > 0),

    -- How long an Entity Configuration is valid. Short by default: it is fetched
    -- on demand and cached by the fetcher, and a long-lived statement is one a
    -- federation keeps trusting after we have changed our mind.
    lifetime_seconds int NOT NULL DEFAULT 86400
        CHECK (lifetime_seconds BETWEEN 300 AND 604800),

    -- Informational metadata for the federation_entity Entity Type (§5.1.1).
    organization_name text,
    homepage_uri      text,
    contacts          text[],

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE core.federation_config IS
    'OpenID Federation 1.0 entity configuration. Absent means this instance is not part of a federation.';

