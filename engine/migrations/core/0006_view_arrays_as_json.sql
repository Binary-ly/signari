-- 0006_view_arrays_as_json.sql
--
-- Emits array-valued columns in core_v1 as JSON rather than PostgreSQL arrays.
--
-- The bug: `core_v1.clients.redirect_uris` was a text[]. Over the wire the pgsql
-- driver hands that to the client as the array LITERAL -- `{https://app.test/cb}`
-- -- not as a structured value. An ORM that casts the column to an array then
-- tries to JSON-decode that literal, fails, and yields an EMPTY LIST.
--
-- Empty, not an error. A client with three registered redirect URIs renders as a
-- client with none, and an operator reading that screen would reasonably conclude
-- the registration is broken. Silent wrong answers are worse than loud failures,
-- especially on the one field whose exact contents decide whether an
-- authorization request is accepted.
--
-- Parsing the array literal client-side is possible but fiddly (quoting, embedded
-- commas, escapes, NULLs). JSON is unambiguous, every language decodes it, and
-- the view is the right place to fix it because the view IS the contract.

SET search_path = core, public;

-- DROP, not CREATE OR REPLACE: PostgreSQL refuses to change a view column's type
-- in place ("cannot change data type of view column ... from text[] to jsonb").
-- Dropping revokes the grants with it, so they are re-issued at the end.
DROP VIEW IF EXISTS core_v1.clients;
DROP VIEW IF EXISTS core_v1.sessions;

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
    to_jsonb(c.pkce_methods)   AS pkce_methods,
    c.id_token_signed_alg,
    c.access_token_format,
    c.access_token_ttl_s,
    c.refresh_token_ttl_s,
    c.backchannel_logout_uri,
    c.created_at,
    c.updated_at,
    -- COALESCE so a client with no registered redirect URI yields [] rather than
    -- SQL NULL. A caller distinguishing "none" from "unknown" should not have to.
    COALESCE(
        (SELECT jsonb_agg(r.redirect_uri ORDER BY r.redirect_uri)
         FROM core.client_redirect_uris r
         WHERE r.client_id = c.client_id),
        '[]'::jsonb
    ) AS redirect_uris
FROM core.clients c;

CREATE VIEW core_v1.sessions AS
SELECT
    s.sid, s.org_id, s.user_id, s.acr,
    to_jsonb(s.amr) AS amr,
    s.auth_time, s.revoked_at, s.revocation_reason, s.not_after,
    s.user_agent, s.created_at,
    (s.revoked_at IS NULL AND s.not_after > now()) AS is_live
FROM core.sessions s;

GRANT SELECT ON core_v1.clients, core_v1.sessions TO signari_admin;
