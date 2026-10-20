-- 0163_audit_hash_version.sql
--
-- Which hash each audit row was written under (3.19). Version 2 hashes
-- occurred_at; version 1, every row before this, did not, so a row's time could
-- be rewritten and the chain still verified. The engine now sets occurred_at
-- itself and writes 2. A release before this one writes the default, 1, and
-- its rows keep verifying as 1.
--
-- Not declared compatible with the previous release: that release verifies
-- every row as version 1, so its export and its doctor would read every row
-- written from here as tampered.

ALTER TABLE core.audit_events ADD COLUMN hash_version smallint NOT NULL DEFAULT 1;

COMMENT ON COLUMN core.audit_events.hash_version IS
    'audit.hashFor version the entry_hash was computed by; 2 covers occurred_at.';
