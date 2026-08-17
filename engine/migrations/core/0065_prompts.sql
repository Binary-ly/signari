-- Questions asked during sign-in: terms acceptance, a missing field, a notice.
--
-- This is the part of a flow builder people actually use. The comparable
-- product lets you drag a prompt stage into a graph; here it is a row and a
-- YAML block, so it diffs in a pull request and cannot be edited by accident in
-- a console at 2am.
--
-- # Where it sits
--
-- Between authentication and the session. Every route that signs somebody in --
-- password, passkey, MFA, Duo, Kerberos, an external provider -- funnels
-- through one function, and the check lives there. A new authentication method
-- therefore cannot forget it, which is the failure that matters: a prompt that
-- covers five routes out of six is a legal notice nobody agreed to on the sixth.
CREATE TABLE core.prompts (
    id      uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id  uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    slug    text NOT NULL,

    title   text NOT NULL,
    body    text,

    -- The fields, as JSON: [{"name":"accept","type":"checkbox","label":"…",
    -- "required":true}]. JSON rather than a table because a prompt's fields are
    -- read and written as one thing and never queried individually.
    fields  jsonb NOT NULL DEFAULT '[]'::jsonb,

    -- once: asked until answered, then never again. The alternative -- asking
    -- every sign-in -- is right for a notice and wrong for terms acceptance,
    -- and getting it backwards is either an annoyance or a compliance failure.
    once    boolean NOT NULL DEFAULT true,

    -- Ordering, when there is more than one.
    position int NOT NULL DEFAULT 0,
    enabled boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, slug)
);

ALTER TABLE core.prompts ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.prompts FORCE ROW LEVEL SECURITY;
-- The engine hatch. Without it the engine reads nothing here and every prompt
-- silently never appears -- see 0058, where this was forgotten once already.
CREATE POLICY prompts_org_isolation ON core.prompts
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

-- What somebody answered, and when.
--
-- Kept rather than reduced to a boolean: "did they accept the terms" is a
-- question asked months later by somebody who needs the date and the version,
-- and a boolean cannot answer it.
CREATE TABLE core.prompt_responses (
    prompt_id uuid NOT NULL REFERENCES core.prompts(id) ON DELETE CASCADE,
    user_id   uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    org_id    uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    answers     jsonb NOT NULL DEFAULT '{}'::jsonb,
    answered_at timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (prompt_id, user_id)
);

CREATE INDEX prompt_responses_by_user ON core.prompt_responses (user_id);

ALTER TABLE core.prompt_responses ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.prompt_responses FORCE ROW LEVEL SECURITY;
CREATE POLICY prompt_responses_org_isolation ON core.prompt_responses
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

COMMENT ON TABLE core.prompts IS
    'Questions asked between authentication and the session: terms acceptance, '
    'a missing field, a notice.';
COMMENT ON COLUMN core.prompts.once IS
    'Asked until answered, then never again. False asks on every sign-in.';
