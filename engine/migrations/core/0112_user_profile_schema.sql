-- Operator-defined user attributes, and the schema that governs them.
--
-- # Why a schema rather than a free-form bag
--
-- A bare jsonb column on core.users would have been three lines and is the
-- wrong shape. An attribute bag is a place personal data accumulates, and one
-- with no declaration has four properties nobody wants: nothing says what may
-- be stored, nothing says who may read it, nothing distinguishes an employee
-- number from a home address, and nothing can decide what a lawful erasure
-- request has to reach.
--
-- So attributes are DECLARED per organisation, and the declaration is what
-- carries the decisions.
--
-- # The one that matters: `personal` decides whether the value is sealed
--
-- A value declared personal is stored SEALED UNDER THE SUBJECT'S OWN KEY, the
-- same key that protects their TOTP secret. `POST /admin/subjects/{id}/erase`
-- destroys that key, so every personal attribute becomes unreadable at the same
-- instant and by the same mechanism -- without erasure needing a list of places
-- to visit, which is the list that goes stale.
--
-- The cost is real and is the reason this is a declaration rather than a
-- default for everything: a sealed value cannot be searched or indexed. An
-- operator cannot ask "which users are in the Munich office" if `office` is
-- sealed. So an attribute that is genuinely not about a person -- an employee
-- type, a cost centre, a licence tier -- may be declared `personal = false` and
-- stored in the clear, where it is queryable.
--
-- **The default is `personal = true`**, and that direction is deliberate.
-- Forgetting to declare an attribute's sensitivity makes it SAFE and
-- inconvenient, rather than convenient and undeletable. The failure this
-- prevents is somebody adding `national_id` in a hurry, and it being plaintext
-- in a table that erasure does not reach.
--
-- # Why not one jsonb column per user
--
-- Because the schema is per organisation and the values are per user, and a
-- jsonb blob makes it impossible to seal one field and not another -- sealing
-- is per value, so the values have to be rows.

CREATE TABLE core.user_attribute_schema (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The attribute's name, as an operator writes it and as a mapper will later
    -- refer to it. Constrained to what can appear in a claim name and a
    -- configuration file without quoting.
    name        text        NOT NULL
                            CHECK (name ~ '^[a-z][a-z0-9_]{0,62}$'),

    display_name text       NOT NULL DEFAULT '',

    -- What the value is. Deliberately few: every one of these has an
    -- unambiguous JSON representation, which is what a claim needs. `string` is
    -- the escape hatch and is not a licence to store JSON in it.
    value_type  text        NOT NULL DEFAULT 'string'
                            CHECK (value_type IN ('string','number','boolean','date')),

    -- SEE THE HEADER. true means the value is sealed under the subject key and
    -- disappears on erasure; false means it is stored in the clear and can be
    -- searched. The default is the safe one.
    personal    boolean     NOT NULL DEFAULT true,

    -- Whether the person themselves may see and set it. An attribute an
    -- administrator maintains -- a clearance level, an employment status -- is
    -- not one its subject should be able to edit, and making that explicit here
    -- is cheaper than discovering it was writable.
    user_readable boolean   NOT NULL DEFAULT false,
    user_writable boolean   NOT NULL DEFAULT false,

    required    boolean     NOT NULL DEFAULT false,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, name),

    -- Writable implies readable. A field somebody can set and cannot see is one
    -- they will set twice.
    CONSTRAINT user_attribute_writable_implies_readable
        CHECK (NOT user_writable OR user_readable)
);

COMMENT ON COLUMN core.user_attribute_schema.personal IS
    'true seals the value under the subject key, so erasure destroys it and it '
    'cannot be searched. false stores it in the clear and searchable. Defaults '
    'to true so that forgetting is safe rather than convenient.';

CREATE TABLE core.user_attributes (
    user_id     uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    attribute_id uuid       NOT NULL REFERENCES core.user_attribute_schema(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- Exactly one of these holds the value, decided by the schema's `personal`
    -- flag at write time.
    --
    -- Two columns rather than one, because they are different KINDS of storage
    -- and not two encodings of one: `value` is queryable and survives erasure,
    -- `value_sealed` is neither. A single column would make "is this searchable"
    -- a property nobody can see in a query plan.
    value        text,
    value_sealed bytea,

    updated_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (user_id, attribute_id),

    -- Never both, and never neither. A row holding both would mean one of them
    -- is stale and nothing says which; a row holding neither is a value that
    -- was never written pretending to be one that was.
    CONSTRAINT user_attribute_has_exactly_one_value
        CHECK ((value IS NULL) <> (value_sealed IS NULL))
);

-- Searching the clear values. Only useful for non-personal attributes by
-- construction, which is the point: a sealed value has no index because it has
-- no searchable content, and that is visible here rather than being a surprise.
CREATE INDEX user_attributes_by_value
    ON core.user_attributes (org_id, attribute_id, value)
    WHERE value IS NOT NULL;

-- Tenant isolation, on both tables, matching the rest of `core`.
ALTER TABLE core.user_attribute_schema ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.user_attribute_schema FORCE ROW LEVEL SECURITY;
CREATE POLICY user_attribute_schema_org_isolation ON core.user_attribute_schema
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

ALTER TABLE core.user_attributes ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.user_attributes FORCE ROW LEVEL SECURITY;
CREATE POLICY user_attributes_org_isolation ON core.user_attributes
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
