-- signari:compatible-with-previous
--
-- 0192_client_admin_api.sql
--
-- Which applications may obtain tokens for the Admin API (6.01): the console,
-- an automation acting as itself. Such a token carries the audience
-- <issuer>/admin, and the Admin API acts on it with the roles its holder is
-- bound to (0191), read per request.
--
-- Off for every client, and only for those an owner designates: an application
-- that could ask for the audience could ask on behalf of anyone with a role who
-- signed in to it, so a third-party application must never be able to. The
-- Admin API reads this on every request, so turning it off refuses the
-- application's tokens from the next one.
--
-- Compatible with the release before, which never reads it.

ALTER TABLE core.clients ADD COLUMN admin_api boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.clients.admin_api IS
    'Whether this client may obtain tokens audienced to the Admin API, which act with its holder''s administrative roles.';
