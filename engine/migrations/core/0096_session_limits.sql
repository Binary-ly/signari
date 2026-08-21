ALTER TABLE core.organizations
    ADD COLUMN max_concurrent_sessions integer NOT NULL DEFAULT 0,
    ADD COLUMN session_limit_behaviour text NOT NULL DEFAULT 'deny';

ALTER TABLE core.organizations
    ADD CONSTRAINT organizations_session_limit_nonnegative
    CHECK (max_concurrent_sessions >= 0);

ALTER TABLE core.organizations
    ADD CONSTRAINT organizations_session_limit_behaviour_known
    CHECK (session_limit_behaviour IN ('deny', 'evict_oldest'));

-- A new termination reason, added to the enumerated CHECK rather than left to
-- fail at runtime. The constraint is the reason this had to be a migration and
-- not just a Go constant: an eviction would otherwise be refused by the database
-- at the moment it was needed, turning a policy into a failed sign-in.
ALTER TABLE core.sessions DROP CONSTRAINT sessions_revocation_reason_check;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason = ANY (ARRAY[
        'logout', 'admin_revoke', 'user_deleted', 'user_deactivated',
        'password_change', 'mfa_reset', 'expired', 'reuse_detected',
        'impersonation_ended', 'shared_signal', 'reauthenticated',
        'session_limit'
    ]));
