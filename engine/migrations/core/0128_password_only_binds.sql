-- 0128_password_only_binds.sql
--
-- Whether a protocol that can carry only a password may sign in somebody the
-- sign-in flow would ask for a second factor.
--
-- # The defect
--
-- LDAP binds, RADIUS PAP and the LDAP and RADIUS outposts verify a password and
-- nothing else. None of them consulted the flow's mfa stage, so an operator who
-- enrolled everybody in an authenticator app, or wrote an unconditional `mfa`
-- stage, had a deployment where the sign-in page demanded a second factor and
-- the directory port next to it accepted the password alone. A stolen password
-- was enough after all; it only had to be typed into a VPN prompt.
--
-- # The setting
--
--   allow            the password is enough on those protocols (the old
--                    behaviour, kept for organisations that existed before this
--                    migration so that no VPN stops working on upgrade)
--   refuse_when_mfa  a bind is refused when the flow would demand a second
--                    factor of this person after a password: under the built-in
--                    flow, anybody with one enrolled; under an unconditional mfa
--                    stage, everybody
--
-- Existing organisations get `allow` and `signari doctor` names the bypass;
-- organisations created from now on get `refuse_when_mfa`. Carrying a code over
-- these protocols (a `;123456` suffix, RADIUS Access-Challenge) is the full fix,
-- and when it exists this setting decides only what happens without one.

SET search_path = core, public;

ALTER TABLE core.organizations
    ADD COLUMN password_only_binds text NOT NULL DEFAULT 'allow'
    CONSTRAINT organizations_password_only_binds_known
    CHECK (password_only_binds IN ('allow', 'refuse_when_mfa'));

ALTER TABLE core.organizations ALTER COLUMN password_only_binds SET DEFAULT 'refuse_when_mfa';

COMMENT ON COLUMN core.organizations.password_only_binds IS
    'Whether LDAP binds, RADIUS PAP and outposts, which carry only a password, may sign in somebody the sign-in flow would ask for a second factor. allow, or refuse_when_mfa.';
