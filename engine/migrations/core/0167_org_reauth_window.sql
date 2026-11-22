-- signari:compatible-with-previous
--
-- 0167_org_reauth_window.sql
--
-- How recently a session must have been authenticated for its holder to
-- change the account (4.04): its sign-in methods, its password, which sessions
-- and applications hold it. It was a constant of ten minutes, applied to the
-- sign-in methods only.
--
-- Compatible with the release before, which ignores the column and holds its
-- own routes to ten minutes, the default here.
ALTER TABLE core.organizations ADD COLUMN reauth_window_s integer NOT NULL DEFAULT 600
    CHECK (reauth_window_s BETWEEN 60 AND 86400);

COMMENT ON COLUMN core.organizations.reauth_window_s IS
    'Seconds since a session was authenticated within which its holder may change '
    'the account from /account; older, they sign in again first. 60 to 86400. Set '
    'with `signari instance reauth-window`.';
