-- 0030_access_policies.sql
--
-- The access policy in force, as the file an operator wrote.
--
-- Stored VERBATIM, not decomposed into tables. The file is the source of truth
-- and lives in version control; this is a copy so the engine can load it
-- without a filesystem dependency. Shredding it into rows would mean the thing
-- reviewed in a pull request and the thing enforced are two different artefacts
-- that have to be kept in step -- which is exactly the drift a file-based
-- policy exists to remove.

SET search_path = core, public;

CREATE TABLE access_policies (
    org_id     uuid        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    document   text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE access_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE access_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY access_policies_org_isolation ON access_policies
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON access_policies TO signari_maintenance;
