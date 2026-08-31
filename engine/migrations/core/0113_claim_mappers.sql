-- Claim mappers: which attribute becomes which claim, for which client.
--
-- # Default deny, and why that is the only defensible default
--
-- An attribute existing does not put it in anybody's token. A mapper is
-- required, per destination, and — where the operator chooses — per client.
--
-- The alternative shape is the one most products ship: attributes flow into
-- tokens automatically and a deny-list holds back the sensitive ones. That
-- inverts the failure. Adding an attribute becomes a disclosure to every relying
-- party already integrated, made by whoever added it, usually without noticing.
-- A deployment that adds `national_insurance_number` to track something
-- internal has, in that shape, just sent it to a dozen third-party
-- applications.
--
-- So nothing is released until somebody says which claim, where, and to whom.
--
-- # Scope-gating, so consent still means something
--
-- A mapper may require a scope. The claim then appears only when the client
-- asked for that scope and the grant carried it — which is what keeps the
-- consent screen honest: a user who declined `profile` must not receive a token
-- that carries their job title anyway.
--
-- A mapper with no required scope releases unconditionally, which is right for
-- something like a tenant identifier that every client needs to function.
--
-- # Why the destination is a column rather than three tables
--
-- Because "put this in the ID token but not the access token" is the common
-- case and the difference matters: an access token is presented to resource
-- servers that the user never saw a consent screen for, so it is the one that
-- leaks furthest. Making the destination explicit forces that choice to be made.

CREATE TABLE core.claim_mappers (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- NULL means every client in the organisation. Naming one narrows it.
    --
    -- Nullable rather than a separate "applies to all" flag: a flag and a value
    -- can disagree, and the disagreement would be resolved differently by
    -- whoever writes the next query.
    client_id   text        REFERENCES core.clients(client_id) ON DELETE CASCADE,

    -- What is being released. Exactly one source.
    attribute_id uuid       NOT NULL REFERENCES core.user_attribute_schema(id) ON DELETE CASCADE,

    -- The claim name as it appears in the token. Not required to match the
    -- attribute name: an internal `staff_number` may be released as
    -- `https://example.test/employee_id` to one client and nothing to another.
    claim_name  text        NOT NULL
                            CHECK (length(claim_name) BETWEEN 1 AND 128),

    -- Where it goes. See the header for why this is explicit.
    destination text        NOT NULL
                            CHECK (destination IN ('id_token','userinfo','access_token')),

    -- The scope a grant must carry for this claim to be released. Empty releases
    -- unconditionally.
    required_scope text     NOT NULL DEFAULT '',

    created_at  timestamptz NOT NULL DEFAULT now(),

    -- One mapping per (client, attribute, destination). Two mappers writing the
    -- same claim from different attributes would make the token's contents
    -- depend on row order.
    UNIQUE (org_id, client_id, attribute_id, destination)
);

-- A claim name may not be one the protocol already defines.
--
-- Overwriting `sub`, `iss`, `aud`, `exp` or `iat` from an operator-defined
-- attribute is not customisation, it is forging the token's own identity: a
-- mapper that set `sub` would let an organisation issue tokens that impersonate
-- any subject at every relying party that trusts this issuer. `amr` and `acr`
-- are here for the same reason one step removed -- they are what a relying party
-- reads to decide whether the authentication was strong enough, and an operator
-- who can set them can claim an MFA that never happened.
ALTER TABLE core.claim_mappers ADD CONSTRAINT claim_mappers_not_a_protocol_claim
    CHECK (claim_name NOT IN (
        'iss','sub','aud','exp','iat','nbf','jti','azp','nonce',
        'auth_time','acr','amr','sid','at_hash','c_hash','s_hash',
        'client_id','scope','cnf'
    ));

CREATE INDEX claim_mappers_lookup
    ON core.claim_mappers (org_id, destination, client_id);

ALTER TABLE core.claim_mappers ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.claim_mappers FORCE ROW LEVEL SECURITY;
CREATE POLICY claim_mappers_org_isolation ON core.claim_mappers
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
