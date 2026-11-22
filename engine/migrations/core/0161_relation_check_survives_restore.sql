-- 0161_relation_check_survives_restore.sql
--
-- A restored database must match its own ledger (3.03). pg_dump writes each
-- CHECK as PostgreSQL renders it and the restore parses that text again; for
-- relation_ids_are_present (0072) the two trees differed, because BETWEEN
-- expands into an AND nested inside the outer one, and the parser flattens a
-- nested AND when it reads the rendering back. So a database restored by the
-- runbook rendered the constraint differently, its fingerprint no longer
-- matched what the ledger recorded, and the engine refused to start on it as
-- drift.
--
-- The same condition, written as the flat chain the parser produces, renders
-- the same before and after a round trip.

ALTER TABLE core.relations DROP CONSTRAINT relation_ids_are_present;
ALTER TABLE core.relations ADD CONSTRAINT relation_ids_are_present CHECK (
    length(subject_id) >= 1 AND length(subject_id) <= 256 AND
    length(object_id) >= 1 AND length(object_id) <= 256);
