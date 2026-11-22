-- signari:compatible-with-previous
--
-- 0232_pairwise_subjects.sql
--
-- A subject that means nothing outside the application it was given to (9.07). A person's
-- id is the same in every token, so two applications can tell they have the same customer by
-- comparing notes. A client set to pairwise names a person by an identifier of its own
-- sector instead: applications that share a sector share it, and nobody else can link them.
-- The identifiers are random and stored, as a SAML persistent NameID is, so there is no salt
-- to keep, an erased person takes theirs with them, and a token's subject reads back to the
-- person without trying every sector.

ALTER TABLE core.clients ADD COLUMN sector text NOT NULL DEFAULT '';

ALTER TABLE core.clients ADD COLUMN subject_type text NOT NULL DEFAULT 'public'
    CHECK (subject_type IN ('public', 'pairwise'))
    CHECK (subject_type = 'public' OR sector <> '');

CREATE TABLE core.pairwise_subjects (
    subject    text        PRIMARY KEY,
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    sector     text        NOT NULL,
    user_id    uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, sector, user_id)
);

CREATE INDEX pairwise_subjects_user ON core.pairwise_subjects (user_id);

ALTER TABLE core.pairwise_subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.pairwise_subjects FORCE ROW LEVEL SECURITY;
CREATE POLICY pairwise_subjects_org_isolation ON core.pairwise_subjects
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.pairwise_subjects TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER pairwise_subjects_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.pairwise_subjects
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
