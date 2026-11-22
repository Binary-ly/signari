-- 0130_saml_entity_id_global.sql
--
-- A SAML service provider's entity ID is unique across the deployment, until
-- there are per-organisation SAML endpoints for two tenants to share one.
--
-- # The defect
--
-- The constraint said UNIQUE (org_id, entity_id) and every lookup said
-- WHERE entity_id = $1. An AuthnRequest names only its issuer, the WS-Federation
-- wtrealm likewise, and the IdP's SSO and SLO endpoints name no organisation --
-- so when two organisations registered the same service provider, each request
-- was answered with one of the two rows at random: the other tenant's signing
-- certificate checked the signature, its ACS URLs received the assertion, its
-- attribute release decided what was in it, and the organisation check then
-- refused whichever person did not belong.
--
-- # Why unique rather than "refuse when ambiguous"
--
-- Refusing an ambiguous entity ID at sign-in would let any tenant switch off
-- another's SAML sign-in by registering the same entity ID. Refusing the second
-- registration puts the limitation where it can be seen: the second tenant is
-- told at registration, rather than the first being broken at sign-in. Serving
-- both needs the IdP endpoints to say which organisation they are for, which
-- is scheduled separately.
--
-- # Why the migration refuses rather than chooses
--
-- As 0129: a duplicate has been answered at random, there is no working
-- configuration to keep, and which tenant keeps the entity ID is the operator's
-- decision.

SET search_path = core, public;

DO $$
DECLARE
    duplicates text;
BEGIN
    SELECT string_agg(format('%s (organisations %s)', entity_id, orgs), '; ')
      INTO duplicates
      FROM (SELECT entity_id, string_agg(org_id::text, ', ' ORDER BY created_at) AS orgs
              FROM core.saml_providers
             GROUP BY entity_id
            HAVING count(*) > 1) d;
    IF duplicates IS NOT NULL THEN
        RAISE EXCEPTION 'SAML service provider entity IDs must be unique across organisations, '
            'because a request names only its entity ID and the SSO endpoint names no '
            'organisation; these are registered by more than one: %', duplicates
            USING HINT = 'Remove all but one of each (signari saml list shows them), or give '
                'one tenant''s registration the entity ID its service provider actually sends '
                'for that tenant if it has a per-tenant one, and run the migration again.';
    END IF;
END $$;

-- The per-organisation constraint stays: `signari apply` upserts on it.
CREATE UNIQUE INDEX saml_providers_entity_id_key ON core.saml_providers (entity_id);
