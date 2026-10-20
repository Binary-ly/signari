-- 0160_ledger_compatibility.sql
--
-- The ledger records whether a binary built for the version before a
-- migration may run against the database it leaves, and which fingerprint
-- scheme computed its fingerprint (3.03).
--
-- A migration declares the first with `-- signari:compatible-with-previous`,
-- checked when it is loaded to add and change nothing. The earlier binary has
-- never seen that file, so it reads the declaration here: it serves a database
-- ahead of it only when every migration since is declared, instead of refusing
-- every database but its own version. That is what lets the previous release
-- keep running through a rolling upgrade, and be rolled back to.
--
-- The scheme is recorded because a binary that fingerprints differently, older
-- or newer, would read every row as drift. Rows written by 0159 carry a server
-- version and were computed by scheme 2, which shipped with it.

ALTER TABLE core.schema_migrations
    ADD COLUMN compatible_with_previous boolean NOT NULL DEFAULT false;
ALTER TABLE core.schema_migrations ADD COLUMN fingerprint_scheme integer;

UPDATE core.schema_migrations SET fingerprint_scheme = 2 WHERE server_version_num IS NOT NULL;

COMMENT ON COLUMN core.schema_migrations.compatible_with_previous IS
    'The migration declared that a binary built for the version before it may run against the result.';
COMMENT ON COLUMN core.schema_migrations.fingerprint_scheme IS
    'migrate.fingerprintScheme of the binary that computed fingerprint; NULL before 0159.';
