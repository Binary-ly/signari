-- 0245_saml_org_endpoint.sql
--
-- Two organisations holding one service provider (8.34). A SaaS application has one entity ID
-- for all its customers, and 0130 let only one of them register it, because the IdP's endpoints
-- named no organisation. Now a provider answers at one of two places: the deployment's endpoints,
-- where an entity ID is still held once, or endpoints of its organisation, where the path says
-- whose it is and the entity ID need only be held once in that organisation.
--
-- Registering a provider somebody else holds puts the new one at its organisation's endpoints and
-- moves nothing. Refusing an entity ID two tenants hold at the deployment's endpoints, which is
-- what this was first planned as, would let any tenant switch off another's sign-in by
-- registering the same entity ID, the reason 0130 gives for not doing that.
--
-- Not compatible with the version before: an older binary looks a provider up by entity ID alone,
-- and with two rows for one it would answer with either.

ALTER TABLE core.saml_providers ADD COLUMN org_endpoint boolean NOT NULL DEFAULT false;

DROP INDEX core.saml_providers_entity_id_key;
CREATE UNIQUE INDEX saml_providers_entity_id_key ON core.saml_providers (entity_id) WHERE NOT org_endpoint;
