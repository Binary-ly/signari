-- signari:compatible-with-previous
-- 0266_org_messages.sql
--
-- An organisation's own words on its pages and in its mail (10.09), one row a message and a
-- language, over the catalogue. Every other way to reword a page is a file on the operator's
-- disk, read at startup, which a tenant cannot reach. These are stored text rather than a
-- catalogue entry: a catalogue message may carry markup because it is ours, and this one is
-- a tenant's, so it is escaped on the way to a page and can only ever be words.

CREATE TABLE core.org_messages (
    org_id     uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    locale     text NOT NULL,
    key        text NOT NULL,
    body       text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 2000),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, locale, key)
);

COMMENT ON TABLE core.org_messages IS
    'An organisation''s wording of one catalogue message in one language. Plain text, '
    'escaped when rendered; a page never reads markup from here.';

ALTER TABLE core.org_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.org_messages FORCE ROW LEVEL SECURITY;
CREATE POLICY org_messages_org_isolation ON core.org_messages
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.org_messages TO signari_maintenance;

CREATE TRIGGER org_messages_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.org_messages
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

CREATE VIEW core_v1.org_messages AS
SELECT m.locale || '/' || m.key AS id, m.org_id, m.locale, m.key, m.body, m.updated_at
  FROM core.org_messages m;

GRANT SELECT ON core_v1.org_messages TO signari_admin;
