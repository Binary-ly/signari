-- 0025_groups.sql
--
-- Groups, and the release of group membership as a claim.
--
-- # Group claims are authorization data
--
-- Everything else this directory emits is identity: who someone is. A group
-- claim is different -- downstream applications gate on it. `groups: ["admin"]`
-- in a token is not a description, it is a grant, and it is enforced by software
-- we do not control and cannot audit.
--
-- Two consequences shape this schema:
--
--   1. Membership is READ AT ISSUANCE, never cached on the session. A session
--      established this morning must not still be minting tokens that claim a
--      group somebody was removed from at lunchtime. There is deliberately no
--      denormalised copy of membership anywhere near `core.sessions`.
--
--   2. Not every client sees groups. Release is per client, because telling a
--      third-party application which internal groups somebody belongs to
--      discloses the shape of the organisation to whoever runs it.

SET search_path = core, public;

CREATE TABLE groups (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The value that appears in a token. Stable, and separate from the display
    -- name for that reason: renaming a group in the console must not silently
    -- revoke access in every application that matched on the old string.
    name         text        NOT NULL,
    display_name text        NOT NULL,
    description  text,

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (org_id, name),
    -- No commas, spaces or quotes: the value travels through JSON arrays, SAML
    -- attribute values and LDAP filters, and a name carrying a delimiter is a
    -- name that means something different in one of them.
    CONSTRAINT groups_name_shape CHECK (name ~ '^[a-zA-Z0-9._-]{1,64}$')
);

CREATE TABLE group_members (
    group_id   uuid        NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    added_at   timestamptz NOT NULL DEFAULT now(),
    -- Who granted it. A group membership is a privilege grant, so it needs the
    -- same provenance as any other one.
    added_by   uuid        REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (group_id, user_id)
);

CREATE INDEX group_members_user_idx ON group_members (user_id);

-- Which clients may see group membership.
--
-- An allow-list, and empty by default. The alternative -- release to everything
-- that asks for the scope -- means the first third-party application anybody
-- integrates learns the organisation's internal structure.
CREATE TABLE client_group_release (
    client_id  text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Empty means every group; otherwise only these. A client that only needs
    -- to know about one group should not be told about the others.
    only_groups text[]     NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id)
);

-- Which SAML providers get groups, and under what attribute name. Different
-- products insist on different names for the same thing.
CREATE TABLE saml_group_release (
    provider_id    uuid    NOT NULL REFERENCES saml_providers(id) ON DELETE CASCADE,
    org_id         uuid    NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    attribute_name text    NOT NULL DEFAULT 'groups',
    only_groups    text[]  NOT NULL DEFAULT '{}',
    PRIMARY KEY (provider_id)
);

DO $$
DECLARE
    t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['groups','group_members','client_group_release','saml_group_release'] LOOP
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

GRANT SELECT ON groups, group_members, client_group_release, saml_group_release
    TO signari_maintenance;
