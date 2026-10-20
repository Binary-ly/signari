-- 0159_ledger_server_version.sql
--
-- The ledger records which PostgreSQL version computed each fingerprint (3.04).
-- A binary built without a pinned fingerprint now compares the live schema
-- with the ledger's latest row, and refuses to start when they differ: before
-- this it compared nothing, so a hand change within a version went unnoticed
-- by every build that was not pinned, which was every shipped build.
--
-- The catalogue may render the same schema differently under another major
-- version, so a row recorded under one is not compared under another; the
-- comparison resumes with the next migration. Rows recorded before this one
-- have no value here, were computed by the fingerprint before it covered the
-- tenant boundary, and are never compared.

ALTER TABLE core.schema_migrations ADD COLUMN server_version_num integer;

COMMENT ON COLUMN core.schema_migrations.server_version_num IS
    'server_version_num of the PostgreSQL that computed this row''s fingerprint; NULL before 0159.';
