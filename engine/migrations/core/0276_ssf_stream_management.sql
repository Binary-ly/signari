-- signari:compatible-with-previous
-- 0276_ssf_stream_management.sql
--
-- What a receiver may change of its own stream (SSF 1.0 §8.1). A stream here carries
-- events about the people its client has met, so "adding" a subject asks for nothing
-- more than that, and removing one is the row worth keeping: a person this receiver
-- would rather not hear about. A description is the receiver's own note on the stream.

ALTER TABLE core.ssf_streams ADD COLUMN description text NOT NULL DEFAULT '';

CREATE TABLE core.ssf_removed_subjects (
    stream_id  uuid        NOT NULL REFERENCES core.ssf_streams(id) ON DELETE CASCADE,
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id    uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    removed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (stream_id, user_id)
);

CREATE INDEX ssf_removed_subjects_org ON core.ssf_removed_subjects (org_id);
CREATE INDEX ssf_removed_subjects_user ON core.ssf_removed_subjects (user_id);

ALTER TABLE core.ssf_removed_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.ssf_removed_subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY ssf_removed_subjects_org_isolation ON core.ssf_removed_subjects
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.ssf_removed_subjects TO signari_maintenance;

CREATE TRIGGER ssf_removed_subjects_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.ssf_removed_subjects
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
