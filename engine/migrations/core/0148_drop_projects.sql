-- 0148_drop_projects.sql
--
-- Drops core.projects and clients.project_id.
--
-- Both have existed since 0002 and nothing reads or writes either: no command,
-- no route, no query. A client's project was always NULL, and a console column
-- for it would have described a grouping nobody could make. Grouping clients
-- by role arrives with relations (11.10), designed for what it is used for.
--
-- The core_v1 view carried project_id, so it is rebuilt without it, with its
-- grant re-issued. Dropping the table takes its row-level policies and its
-- configuration-version trigger with it.

SET search_path = core, public;

DROP VIEW core_v1.clients;

ALTER TABLE clients DROP COLUMN project_id;
DROP TABLE projects;

CREATE VIEW core_v1.clients AS
SELECT
    c.client_id,
    c.org_id,
    c.display_name,
    c.client_type,
    c.enabled,
    to_jsonb(c.grant_types)    AS grant_types,
    to_jsonb(c.response_types) AS response_types,
    to_jsonb(c.scopes)         AS scopes,
    c.require_pkce,
    c.id_token_signed_alg,
    c.access_token_ttl_s,
    c.refresh_token_ttl_s,
    c.backchannel_logout_uri,
    c.created_at,
    c.updated_at,
    COALESCE(
        (SELECT jsonb_agg(r.redirect_uri ORDER BY r.redirect_uri)
         FROM core.client_redirect_uris r
         WHERE r.client_id = c.client_id),
        '[]'::jsonb
    ) AS redirect_uris
FROM core.clients c;

GRANT SELECT ON core_v1.clients TO signari_admin;
