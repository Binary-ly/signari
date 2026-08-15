-- An audit row must never be mutated. Not even by a foreign key.
--
-- # The bug this fixes
--
-- core.audit_events had two foreign keys with ON DELETE SET NULL:
--
--   org_id          -> core.organizations
--   admin_token_id  -> core.admin_tokens
--
-- Both of those columns are INSIDE the chain hash. So deleting an organisation,
-- or revoking and deleting an admin token, silently rewrote historical audit
-- rows -- and every rewritten row then failed verification.
--
-- The consequence is worse than it sounds. The selling point of a hash-chained
-- trail is that deletion and alteration are DETECTABLE. A chain that reports
-- "tampered" after an ordinary administrative action is a smoke alarm that goes
-- off when somebody makes toast: within a month nobody looks at it, and the real
-- signal is lost with the false ones.
--
-- Demonstrated before fixing: insert an audit row attributed to a token, delete
-- the token, and admin_token_id goes from set to NULL underneath it.
--
-- # Why dropping the constraints is right
--
-- The trail is append-only and historical. It records what was true at the time,
-- and an entry naming an organisation or a token that no longer exists is not
-- dangling -- it is the point. Referential integrity is a rule for current
-- state; an audit row is not current state.
--
-- The columns keep their values. Nothing is lost except the ability of an
-- unrelated DELETE to reach in and change history.

ALTER TABLE core.audit_events DROP CONSTRAINT audit_events_org_id_fkey;
ALTER TABLE core.audit_events DROP CONSTRAINT audit_events_admin_token_id_fkey;

COMMENT ON COLUMN core.audit_events.org_id IS
    'The organisation at the time of the event. Deliberately NOT a foreign key: '
    'this column is inside the chain hash, so a referential action that changed '
    'it would rewrite history and break verification.';

COMMENT ON COLUMN core.audit_events.admin_token_id IS
    'The admin token that caused this change, at the time. Deliberately NOT a '
    'foreign key, for the same reason as org_id -- revoking a token must not '
    'alter the record of what it did.';
