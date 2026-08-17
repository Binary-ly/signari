-- An organisation's appearance on the pages a user sees.
--
-- # Tokens, not CSS
--
-- The obvious design is a text column holding custom CSS, which is what the
-- other products offer. It is also stored cross-site scripting aimed at the
-- worst possible page: CSS can pull resources from anywhere, attribute
-- selectors with url() exfiltrate the page's own state, and an administrator
-- who can restyle the sign-in form can restyle it into one that posts
-- elsewhere.
--
-- So this stores a fixed set of tokens. Every colour is validated as a hex
-- literal before it is written and again before it is emitted, and there is no
-- path from a row here to arbitrary markup or arbitrary style rules.
--
-- # Why this is per instance
--
-- An instance is one issuer on one hostname, which is the same unit the other
-- products key branding on when they key it on domain. Serving two brands from
-- one hostname would mean guessing which one a visitor should see before they
-- have identified themselves, and guessing wrong shows one customer another
-- customer's logo.
CREATE TABLE core.brands (
    instance_id uuid PRIMARY KEY REFERENCES core.instances(id) ON DELETE CASCADE,

    product_name text,
    logo_url     text,
    support_url  text,

    -- All four or none. A custom background against a default text colour is
    -- how a page ends up unreadable, so the engine refuses a partial palette.
    colour_primary    text,
    colour_on_primary text,
    colour_background text,
    colour_text       text,

    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT brands_palette_is_whole CHECK (
        num_nonnulls(colour_primary, colour_on_primary,
                     colour_background, colour_text) IN (0, 4)),

    -- Repeated here as well as in the engine. A colour reaching the stylesheet
    -- from a repair script that never went through the engine is exactly the
    -- case the application-level check cannot cover.
    CONSTRAINT brands_colours_are_hex CHECK (
        (colour_primary    IS NULL OR colour_primary    ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$') AND
        (colour_on_primary IS NULL OR colour_on_primary ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$') AND
        (colour_background IS NULL OR colour_background ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$') AND
        (colour_text       IS NULL OR colour_text       ~ '^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6})$')),

    CONSTRAINT brands_urls_are_https CHECK (
        (logo_url    IS NULL OR logo_url    LIKE 'https://%') AND
        (support_url IS NULL OR support_url LIKE 'https://%'))
);

COMMENT ON TABLE core.brands IS
    'Per-instance appearance: a product name, a logo, and four validated '
    'colours. Deliberately not a CSS column -- see the migration for why.';
