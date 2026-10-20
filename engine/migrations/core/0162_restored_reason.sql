-- 0162_restored_reason.sql
--
-- A session ended because the database was restored (3.10). A restore brings
-- back every session as it was at the backup, including the ones ended since,
-- so `signari restore finalize` ends all of them, tells the applications, and
-- records why.

ALTER TABLE core.sessions DROP CONSTRAINT sessions_revocation_reason_check;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason = ANY (ARRAY[
        'logout', 'admin_revoke', 'user_deleted', 'user_deactivated',
        'password_change', 'mfa_reset', 'expired', 'reuse_detected',
        'impersonation_ended', 'shared_signal', 'reauthenticated',
        'session_limit', 'user_revoke', 'restored']));
