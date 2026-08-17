-- Outposts that authenticate a desktop or a workstation login.
--
-- A Windows credential provider, a PAM module, a kiosk. They cannot render a
-- web page, so they cannot use the ordinary sign-in flow: the user types a
-- username, a password and a code into a native dialog, and something has to
-- answer "yes or no" in one exchange.
--
-- A distinct kind rather than reusing 'ldap' or 'radius' because the capability
-- differs: this one verifies a SECOND FACTOR as well as a password, and a token
-- that can do that should not be issued to something that only needs a bind.
ALTER TABLE core.outposts DROP CONSTRAINT IF EXISTS outposts_kind_check;
ALTER TABLE core.outposts
    ADD CONSTRAINT outposts_kind_check
        CHECK (kind IN ('ldap', 'radius', 'proxy', 'desktop'));

COMMENT ON COLUMN core.outposts.kind IS
    'ldap, radius, proxy or desktop. desktop may verify a second factor as well '
    'as a password, which the others may not.';
