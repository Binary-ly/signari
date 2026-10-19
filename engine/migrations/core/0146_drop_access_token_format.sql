-- 0146_drop_access_token_format.sql
--
-- Drops clients.access_token_format.
--
-- The column said whether a client's access tokens were JWTs or opaque, and
-- defaulted to 'jwt'. Every access token this engine mints is a JWT, and
-- nothing read the column: a console showing 'opaque' would have described a
-- token that did not exist. Opaque tokens, if they come, come with the code
-- that mints and introspects them, and the column with them.
--
-- The core_v1 view carried it, so it is rebuilt without it, with its grant
-- re-issued.

SET search_path = core, public;

DROP VIEW core_v1.clients;

ALTER TABLE clients DROP COLUMN access_token_format;

CREATE VIEW core_v1.clients AS
SELECT
    c.client_id,
    c.org_id,
    c.project_id,
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
