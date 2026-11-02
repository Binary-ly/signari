-- signari:compatible-with-previous
-- 0265_org_brands.sql
--
-- An organisation's appearance over its instance's (10.09). Two tenants on one hostname shared
-- one brand, so the second to set a logo replaced the first. This no longer guesses before
-- identity: a page takes the organisation of the client whose request it is answering, or of
-- the session it is answering, and a bare page on a deployment of several wears the instance's.

CREATE TABLE core.org_brands (
    org_id uuid PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,

    product_name text,
    logo_url     text,
    support_url  text,

    -- All four or none, as on core.brands, and passed down as a whole: a background from one
    -- brand under text from another is a pair nobody checked for contrast.
    colour_primary    text,
    colour_on_primary text,
    colour_background text,
    colour_text       text,

    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT org_brands_palette_is_whole CHECK (
        num_nonnulls(colour_primary, colour_on_primary,
                     colour_background, colour_text) IN (0, 4)),
    CONSTRAINT org_brands_primary_is_hex CHECK (
        colour_primary IS NULL OR colour_primary ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
    CONSTRAINT org_brands_on_primary_is_hex CHECK (
        colour_on_primary IS NULL OR colour_on_primary ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
    CONSTRAINT org_brands_background_is_hex CHECK (
        colour_background IS NULL OR colour_background ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
    CONSTRAINT org_brands_text_is_hex CHECK (
        colour_text IS NULL OR colour_text ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$'),
    CONSTRAINT org_brands_logo_is_https CHECK (logo_url IS NULL OR logo_url LIKE 'https://%'),
    CONSTRAINT org_brands_support_is_https CHECK (support_url IS NULL OR support_url LIKE 'https://%')
);

COMMENT ON TABLE core.org_brands IS
    'An organisation''s appearance, worn over its instance''s: a name, a logo and four validated '
    'colours, and what it leaves out falls through. Deliberately not a CSS column; see 0056.';

ALTER TABLE core.org_brands ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.org_brands FORCE ROW LEVEL SECURITY;
CREATE POLICY org_brands_org_isolation ON core.org_brands
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.org_brands TO signari_maintenance;

CREATE TRIGGER org_brands_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.org_brands
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

CREATE VIEW core_v1.org_brands AS
SELECT b.org_id, b.product_name, b.logo_url, b.support_url, b.colour_primary,
       b.colour_on_primary, b.colour_background, b.colour_text, b.updated_at
  FROM core.org_brands b;

GRANT SELECT ON core_v1.org_brands TO signari_admin;
