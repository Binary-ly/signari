-- 0091_reauthenticated_reason.sql
--
-- A termination reason for the session replaced by a re-authentication.
--
-- ASVS 5.0.0 V7.2.4: "Verify that the application generates a new session token
-- on user authentication, including re-authentication, and TERMINATES THE CURRENT
-- SESSION TOKEN."
--
-- The first half was always done -- completeSignIn mints a fresh sid and cookie
-- token every time, so session fixation has never worked here. The second half
-- was not: the previous session row stayed live until not_after.
--
-- The case that matters is step-up. A user signs in with a password (acr=1),
-- something asks for another factor, they re-authenticate, and they now hold an
-- acr=2 session. The acr=1 session remained valid for hours. Anyone holding that
-- earlier cookie kept a working password-only session -- and the user
-- re-authenticated precisely because something warranted it.
--
-- A distinct reason rather than reusing 'logout': an operator reading the audit
-- trail should be able to tell a session that ended because somebody left from
-- one that ended because it was superseded, and the CAEP session-revoked event
-- carries this value to relying parties.

SET search_path = core, public;

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_revocation_reason_check;

ALTER TABLE sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason IN
        ('logout','admin_revoke','user_deleted','user_deactivated',
         'password_change','mfa_reset','expired','reuse_detected',
         'impersonation_ended','shared_signal','reauthenticated'));
