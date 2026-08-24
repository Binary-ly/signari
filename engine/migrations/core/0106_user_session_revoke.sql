-- A revocation reason for a session the user ended themselves, from the
-- self-service account console.
--
-- ASVS V7.5.2 asks that a user can "view and ... terminate any or all currently
-- active sessions". The mechanism (TerminateSessions) already existed and every
-- other caller had a reason on the constraint; a user ending their own session
-- from /account/sessions did not, and 'logout' is the wrong word for it -- the
-- session being ended is usually a DIFFERENT one than the browser making the
-- request (a phone left signed in, a shared machine), which is precisely why the
-- feature exists. A distinct reason keeps the audit trail and the CAEP
-- session-revoked notice honest about who decided and why.
ALTER TABLE core.sessions DROP CONSTRAINT sessions_revocation_reason_check;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason = ANY (ARRAY[
        'logout', 'admin_revoke', 'user_deleted', 'user_deactivated',
        'password_change', 'mfa_reset', 'expired', 'reuse_detected',
        'impersonation_ended', 'shared_signal', 'reauthenticated',
        'session_limit', 'user_revoke']));
