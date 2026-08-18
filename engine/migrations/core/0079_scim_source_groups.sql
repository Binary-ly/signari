CREATE TABLE core.scim_source_group_links (
    source_id    uuid NOT NULL REFERENCES core.scim_sources(id) ON DELETE CASCADE,

    external_id  text NOT NULL,

    group_id     uuid NOT NULL REFERENCES core.groups(id) ON DELETE CASCADE,
    resource_id  uuid NOT NULL DEFAULT gen_random_uuid(),

    -- The upstream's display name, kept verbatim.
    --
    -- core.groups.name is constrained to ^[a-zA-Z0-9._-]{1,64}$ because it
    -- travels through JSON arrays, SAML attribute values and LDAP filters, where
    -- a space or a quote means something else. Upstream names routinely contain
    -- both ("Engineering Team", "Finance & Legal"), so the name is derived and
    -- the original is stored here -- otherwise every provisioned group would be
    -- refused by a CHECK constraint the upstream can neither see nor satisfy.
    display_name text NOT NULL,

    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (source_id, external_id)
);

CREATE UNIQUE INDEX scim_source_group_links_resource
    ON core.scim_source_group_links (source_id, resource_id);

-- One upstream group per local group per source. Without it two upstream records
-- could both claim the same group and each would overwrite the other's members.
CREATE UNIQUE INDEX scim_source_group_links_group
    ON core.scim_source_group_links (source_id, group_id);

COMMENT ON TABLE core.scim_source_group_links IS
    'Maps an upstream SCIM group to a local core.groups row. Matched on external_id only, because displayName changes when somebody renames a group.';
