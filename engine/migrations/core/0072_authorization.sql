-- The authorization layer: answering "may Alice edit document 42?"
--
-- # Why this belongs in the identity provider
--
-- A standalone policy decision point receives whatever the calling application
-- claims about the subject. It has to: it has no other source. So an
-- application that says "this user is in group finance" is believed, and the
-- authorization decision is only as trustworthy as the least careful service
-- that calls it.
--
-- We already know. The subject's groups, whether they proved a second factor,
-- what their device posture was, how risky the session looked -- all of that
-- comes from the session WE issued, not from the request body. That is not a
-- convenience; it is the difference between a decision about a real person and
-- a decision about a claim.
--
-- # Relations, not roles
--
-- A relation is (subject, relation, object): `alice member group:finance`,
-- `group:finance editor document:42`. Roles are the special case where the
-- object is the whole application, and they collapse the moment somebody asks
-- "who can edit THIS document" -- which is the question that actually gets
-- asked. The shape is Zanzibar's because that model has held up.

CREATE TABLE core.relations (
    id          bigserial   PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- `user:alice`, `group:finance`. Typed because an untyped id collides:
    -- a group and a document may both be called "reports", and a relation that
    -- cannot tell them apart grants the wrong one.
    subject_type text       NOT NULL,
    subject_id   text       NOT NULL,

    relation     text       NOT NULL,

    object_type  text       NOT NULL,
    object_id    text       NOT NULL,

    -- Who granted it, and when. A relation is a privilege grant and needs the
    -- same provenance as any other one.
    granted_by  uuid        REFERENCES core.users(id) ON DELETE SET NULL,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    -- Optional expiry, so temporary access is temporary without anyone having
    -- to remember to take it away.
    expires_at  timestamptz,

    UNIQUE (org_id, subject_type, subject_id, relation, object_type, object_id),

    -- Shapes, so a typo cannot create a relation nothing will ever match.
    CONSTRAINT relation_names_are_plain CHECK (
        subject_type ~ '^[a-z][a-z0-9_-]{0,63}$' AND
        relation     ~ '^[a-z][a-z0-9_-]{0,63}$' AND
        object_type  ~ '^[a-z][a-z0-9_-]{0,63}$'),
    CONSTRAINT relation_ids_are_present CHECK (
        length(subject_id) BETWEEN 1 AND 256 AND length(object_id) BETWEEN 1 AND 256)
);

-- The two directions the evaluator walks.
CREATE INDEX relations_forward
    ON core.relations (org_id, subject_type, subject_id, relation);
CREATE INDEX relations_reverse
    ON core.relations (org_id, object_type, object_id, relation);

ALTER TABLE core.relations ENABLE ROW LEVEL SECURITY;

-- The engine hatch; see 0058. Without core.is_engine() the engine reads zero
-- rows, and a superuser development DSN bypasses RLS entirely, so the failure
-- is invisible until deployment -- here it would show as every request denied.
CREATE POLICY relations_org ON core.relations
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON core.relations TO signari_engine;
GRANT USAGE, SELECT ON SEQUENCE core.relations_id_seq TO signari_engine;

-- The model: which relations imply which, and which permissions they grant.
--
-- Stored per organisation rather than compiled in, because "an editor is also a
-- viewer" is a statement about somebody's application, not about ours.
CREATE TABLE core.authorization_models (
    org_id      uuid        PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- The YAML the operator wrote, kept verbatim so `signari policy show` can
    -- print what they wrote rather than a re-serialisation of what we parsed.
    source      text        NOT NULL,
    -- The parsed form, so evaluation does not re-parse per request.
    compiled    jsonb       NOT NULL,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    updated_by  uuid        REFERENCES core.users(id) ON DELETE SET NULL
);

ALTER TABLE core.authorization_models ENABLE ROW LEVEL SECURITY;
CREATE POLICY authorization_models_org ON core.authorization_models
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON core.authorization_models TO signari_engine;

COMMENT ON TABLE core.relations IS
    'Zanzibar-style tuples: (subject, relation, object). The authorization layer.';

-- A policy decision point is asked questions by applications, and each needs a
-- credential scoped to one organisation. That is exactly what an outpost token
-- already is, so `pdp` becomes a kind rather than a parallel credential type
-- with its own issuance, rate limiting and revocation to get wrong separately.
--
-- The kind CHECK enumerates them, so a new one must be added HERE or every
-- `outpost create -kind-outpost pdp` fails at runtime with a constraint
-- violation -- which the Go code compiles perfectly happily.
ALTER TABLE core.outposts DROP CONSTRAINT outposts_kind_check;
ALTER TABLE core.outposts ADD CONSTRAINT outposts_kind_check
    CHECK (kind IN ('ldap','radius','proxy','desktop','pdp'));
