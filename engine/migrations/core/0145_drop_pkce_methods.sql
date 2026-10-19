-- 0145_drop_pkce_methods.sql
--
-- Drops clients.pkce_methods.
--
-- # Why it goes rather than getting a writer
--
-- The column held the PKCE methods a client could use, defaulting to S256, and
-- nothing could write it. The authorization endpoint refuses every method but
-- S256 before it consults the column, because RFC 7636's `plain` sends the
-- verifier itself as the challenge and protects nothing against an attacker
-- who can read the authorization request. So there was never a value it could
-- be set to that would change anything: a writer would have offered a choice
-- with one answer, and `plain` stayed permitted by the original CHECK only on
-- paper. The rule lives in the code that enforces it.
--
-- The core_v1 view carried the column, so it is rebuilt without it, with its
-- grant re-issued (DROP revokes it).

SET search_path = core, public;

DROP VIEW core_v1.clients;

ALTER TABLE clients DROP COLUMN pkce_methods;

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
    c.access_token_format,
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
