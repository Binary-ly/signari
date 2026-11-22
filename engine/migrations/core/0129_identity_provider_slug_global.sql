-- 0129_identity_provider_slug_global.sql
--
-- An identity provider's slug is unique across the deployment, not per
-- organisation.
--
-- # The defect
--
-- The slug is the sign-in route -- /login/with/<slug>, /login/callback/<slug>,
-- /saml/source/<slug>/acs -- and those URLs carry no organisation. The
-- constraint said UNIQUE (org_id, slug) and the lookup said WHERE slug = $1, so
-- a second organisation registering `google` made the route answer with one of
-- the two rows at random: some of the first organisation's people were sent
-- through the second's upstream configuration, and signed in or created as
-- accounts in the organisation that had registered it.
--
-- # Why the migration refuses rather than renames
--
-- A deployment holding the same slug in two organisations has been routing it at
-- random, so there is no working configuration to preserve -- but choosing which
-- of the two keeps the name decides whose upstream registration keeps working,
-- and that is the operator's decision. The migration names the duplicates and
-- stops; renaming one and registering its new callback URL upstream is the fix.

SET search_path = core, public;

DO $$
DECLARE
    duplicates text;
BEGIN
    SELECT string_agg(format('%s (organisations %s)', slug, orgs), '; ')
      INTO duplicates
      FROM (SELECT slug, string_agg(org_id::text, ', ' ORDER BY created_at) AS orgs
              FROM core.identity_providers
             GROUP BY slug
            HAVING count(*) > 1) d;
    IF duplicates IS NOT NULL THEN
        RAISE EXCEPTION 'identity provider slugs must be unique across organisations, because '
            'they are the sign-in URL and the URL names no organisation; these are held by more '
            'than one: %', duplicates
            USING HINT = 'Rename all but one of each, for example UPDATE core.identity_providers '
                'SET slug = ''google-acme'' WHERE org_id = ''<uuid>'' AND slug = ''google''; then '
                'register /login/callback/<new slug> (or /saml/source/<new slug>/acs) at that '
                'upstream provider, and run the migration again.';
    END IF;
END $$;

CREATE UNIQUE INDEX identity_providers_slug_key ON core.identity_providers (slug);
ALTER TABLE core.identity_providers DROP CONSTRAINT identity_providers_org_id_slug_key;
