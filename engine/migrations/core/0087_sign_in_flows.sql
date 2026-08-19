-- 0087_sign_in_flows.sql
--
-- The sign-in flow in force, as the file an operator wrote.
--
-- Stored verbatim, for the same reason as access_policies (0030): the file is
-- the source of truth and lives in version control, and this is a copy so the
-- engine can load it without a filesystem dependency. Decomposing a flow into
-- stage and binding rows -- which is how the systems this is measured against
-- model it -- means the artefact reviewed in a pull request and the artefact
-- enforced are two different things that must be kept in step.
--
-- # A row here is a document that has already been proved safe
--
-- Nothing reaches this table until internal/flow has parsed it, run its own
-- test cases, and established statically that none of its journeys can issue a
-- session without proving who the subject is. `signari flow apply` does that
-- before the INSERT.
--
-- The engine repeats all of it on load anyway. That is not belt-and-braces for
-- its own sake: a document written straight into this table with psql has
-- bypassed the CLI, and the load path is the last place to catch it. When the
-- stored document fails, the loader keeps the PREVIOUS flow rather than
-- dropping to none -- an absent flow would mean falling back to the built-in
-- one, which is a different journey than the operator is expecting and would
-- change silently under them.
--
-- An org with no row here runs the built-in flows, which is the behaviour every
-- deployment had before flows existed.

SET search_path = core, public;

CREATE TABLE sign_in_flows (
    org_id     uuid        PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
    document   text        NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE sign_in_flows ENABLE ROW LEVEL SECURITY;
ALTER TABLE sign_in_flows FORCE ROW LEVEL SECURITY;
CREATE POLICY sign_in_flows_org_isolation ON sign_in_flows
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON sign_in_flows TO signari_maintenance;

COMMENT ON TABLE sign_in_flows IS
    'The sign-in journey as a file. Every document here has passed the static safety analysis in internal/flow: no journey it admits can issue a session without proving the subject, and none changes a credential before proving one. An org with no row runs the built-in flows.';
