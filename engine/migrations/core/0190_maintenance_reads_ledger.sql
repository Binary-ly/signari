-- signari:compatible-with-previous
--
-- 0190_maintenance_reads_ledger.sql
--
-- signari_maintenance may read which schema version is applied (6.08). Every
-- other core table it can read by the default privileges 0001 set, and the
-- ledger, made by the bootstrap before them, it could not, so GET
-- /admin/system failed for anything holding that role. Read only: the ledger
-- is written by `signari migrate` alone.

GRANT SELECT ON core.schema_migrations TO signari_maintenance;
