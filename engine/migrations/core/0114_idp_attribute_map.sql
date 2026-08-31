-- Mapping an upstream provider's claims onto this deployment's attributes.
--
-- # Default deny, in the other direction
--
-- `claim_mappers` decides what leaves this system. This decides what an upstream
-- identity provider may put INTO it, and the answer is nothing until an operator
-- names a claim.
--
-- That matters more than the outbound direction, because the source is a party
-- this deployment does not control. A shape that copied every claim into an
-- attribute bag would let whoever runs the upstream provider write arbitrary
-- state onto local accounts — and if any access policy ever reads an attribute,
-- that is the upstream provider deciding local authorization.
--
-- Naming the claim is the operator saying "I trust this provider for this
-- fact". Nothing else is read, so `federation.idTokenClaims`'s rule — anything
-- not listed cannot be trusted by accident — survives; the list has moved from a
-- Go struct to configuration for the claims that were always deployment-specific.
--
-- # Values are attacker-influenced and therefore bounded
--
-- The upstream provider chooses these strings. `max_length` is enforced when the
-- value is applied, so a hostile or broken provider cannot write megabytes per
-- user per sign-in, and the default is small enough to be a real bound rather
-- than a formality.

CREATE TABLE core.idp_attribute_map (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_id uuid        NOT NULL REFERENCES core.identity_providers(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The claim name as the upstream provider spells it.
    upstream_claim text     NOT NULL
                            CHECK (length(upstream_claim) BETWEEN 1 AND 128),

    -- The local attribute it lands in. A foreign key rather than a name, so an
    -- attribute cannot be dropped while a mapping still points at it.
    attribute_id uuid       NOT NULL REFERENCES core.user_attribute_schema(id) ON DELETE CASCADE,

    -- Whether a sign-in may overwrite a value already present.
    --
    -- Default false, and that direction is the careful one: an attribute an
    -- administrator set by hand should not be silently replaced by whatever the
    -- upstream provider says on the next sign-in. Turning it on is choosing the
    -- provider as the system of record for that field.
    overwrite   boolean     NOT NULL DEFAULT false,

    -- Bound on the accepted value. Longer is refused, not truncated: a truncated
    -- value is a wrong value that looks like a right one.
    max_length  integer     NOT NULL DEFAULT 256
                            CHECK (max_length BETWEEN 1 AND 4096),

    created_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (provider_id, upstream_claim, attribute_id)
);

CREATE INDEX idp_attribute_map_by_provider ON core.idp_attribute_map (provider_id);

ALTER TABLE core.idp_attribute_map ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.idp_attribute_map FORCE ROW LEVEL SECURITY;
CREATE POLICY idp_attribute_map_org_isolation ON core.idp_attribute_map
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
