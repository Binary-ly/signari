-- signari:compatible-with-previous
-- 0269_console_views.sql
--
-- What the console's remaining screens read (6.13): an organisation's scopes, claim mappers,
-- attributes, directories and inbound SCIM sources. Each leaves out what it would not show
-- anyway, so that no credential is a column the admin role can select: a directory's sealed
-- credentials and a source's token hash stay in core, and a screen cannot reach what is not here.

CREATE VIEW core_v1.scopes AS
SELECT s.id, s.org_id, s.name, s.display_name, s.description, s.advertise, s.created_at
  FROM core.scopes s;

CREATE VIEW core_v1.claim_mappers AS
SELECT m.id, m.org_id, m.client_id, m.claim_name, m.destination, m.required_scope, m.source,
       m.source_value, m.transform, m.created_at, a.name AS attribute
  FROM core.claim_mappers m
  LEFT JOIN core.user_attribute_schema a ON a.id = m.attribute_id;

CREATE VIEW core_v1.attribute_schema AS
SELECT a.id, a.org_id, a.name, a.display_name, a.value_type, a.personal, a.user_readable,
       a.user_writable, a.required, a.created_at
  FROM core.user_attribute_schema a;

CREATE VIEW core_v1.directory_sources AS
SELECT d.id, d.org_id, d.kind, d.slug, d.display_name, d.enabled, d.dry_run, d.on_missing,
       d.last_sync_at, d.last_error, d.last_created, d.last_updated, d.last_deactivated, d.next_sync_at
  FROM core.directory_sources d;

CREATE VIEW core_v1.scim_sources AS
SELECT s.id, s.org_id, s.slug, s.display_name, s.on_delete, s.enabled, s.last_seen_at, s.created_at
  FROM core.scim_sources s;

GRANT SELECT ON core_v1.scopes, core_v1.claim_mappers, core_v1.attribute_schema,
    core_v1.directory_sources, core_v1.scim_sources TO signari_admin;
