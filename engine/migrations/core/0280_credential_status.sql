-- signari:compatible-with-previous
-- 0280_credential_status.sql
--
-- Taking a credential back once it has been issued, with a Token Status List: a
-- configuration asks for it, each credential then carries a place in a list, and the
-- list is signed for anybody to fetch. Until this nothing issued could be revoked,
-- because nothing issued was remembered.

ALTER TABLE core.credential_configurations ADD COLUMN revocable boolean NOT NULL DEFAULT false;

-- One herd of credentials, §12.5. `full` stops it taking more, well before every place
-- is used: the rest stay unset as decoys, and a random place is quick to find.
CREATE TABLE core.credential_status_lists (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    allocated  integer     NOT NULL DEFAULT 0,
    full_up    boolean     NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX credential_status_lists_filling ON core.credential_status_lists (org_id, full_up, created_at, id);
CREATE INDEX credential_status_lists_finished ON core.credential_status_lists (id) WHERE full_up;

ALTER TABLE core.credential_status_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.credential_status_lists FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_status_lists_org_isolation ON core.credential_status_lists
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.credential_status_lists TO signari_maintenance;

CREATE TRIGGER credential_status_lists_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.credential_status_lists
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- What was issued and where its bit is. The primary key is what §13.3's "MUST prevent
-- any unintended double allocation" comes to. A row stays as long as its list, since a
-- place freed would be a place handed out twice.
--
-- user_id goes to NULL with the person, and a place with nobody behind it reads as
-- revoked: every way a person can be deleted ends here, and no way should leave their
-- credential saying VALID.
CREATE TABLE core.issued_credentials (
    id            uuid        NOT NULL DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id       uuid        REFERENCES core.users(id) ON DELETE SET NULL,
    configuration text        NOT NULL,
    list_id       uuid        NOT NULL REFERENCES core.credential_status_lists(id) ON DELETE CASCADE,
    idx           integer     NOT NULL,
    issued_at     timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz,
    revoked_at    timestamptz,
    PRIMARY KEY (list_id, idx),
    CONSTRAINT issued_credentials_id_unique UNIQUE (id),
    CONSTRAINT issued_credentials_idx_positive CHECK (idx >= 0)
);

CREATE INDEX issued_credentials_org ON core.issued_credentials (org_id, id);
CREATE INDEX issued_credentials_user ON core.issued_credentials (user_id, id);
CREATE INDEX issued_credentials_unset ON core.issued_credentials (list_id, idx)
    WHERE revoked_at IS NOT NULL OR user_id IS NULL;

ALTER TABLE core.issued_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.issued_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY issued_credentials_org_isolation ON core.issued_credentials
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.issued_credentials TO signari_maintenance;

CREATE TRIGGER issued_credentials_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.issued_credentials
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
