-- signari:compatible-with-previous
--
-- 0304_client_localized_names.sql
--
-- A client's name in other languages (10.12), RFC 7591 section 2.2's "client_name#ja": a
-- BCP 47 tag after the member name, compared without regard to case, which is what a
-- page that names the client shows to a person whose language it is. The untagged
-- display name stays the name used as is everywhere else, as the section says a value
-- without a tag must be. Only the name: it is the one human-readable field this server
-- shows, and storing logo or policy addresses in languages nothing displays would be
-- metadata nothing reads.
--
-- The tag is kept as it was written, so a registrant reading its registration back finds
-- the member it sent; one name per tag whatever its case. An earlier binary reads only the
-- untagged name and shows that.

CREATE TABLE core.client_localized_names (
    client_id text NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    org_id    uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- RFC 5646's shape: subtags of one to eight letters and digits, joined by hyphens.
    -- That it is a tag the language registry knows is checked where it is written.
    tag       text NOT NULL CHECK (tag ~ '^[A-Za-z]{1,8}(-[A-Za-z0-9]{1,8})*$'),
    name      text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 60),
    PRIMARY KEY (client_id, tag)
);

CREATE UNIQUE INDEX client_localized_names_one_per_tag ON core.client_localized_names (client_id, lower(tag));

ALTER TABLE core.client_localized_names ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.client_localized_names FORCE ROW LEVEL SECURITY;
CREATE POLICY client_localized_names_org_isolation ON core.client_localized_names
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.client_localized_names TO signari_maintenance;

CREATE TRIGGER client_localized_names_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.client_localized_names
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.client_localized_names IS
    'a client''s name in a language, RFC 7591 client_name#<BCP 47 tag>; the untagged name is clients.display_name';
