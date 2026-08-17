-- A native provisioning target has no base URL to be https.
--
-- scim_targets_https predates native targets and requires every row's base_url
-- to be an https URL. Google and Entra targets have no base_url at all -- the
-- endpoint is the provider's own API, fixed and not configurable -- so the
-- constraint refused them.
--
-- Rewritten to apply where it means something. A SCIM target must still be
-- https: it is a URL an operator supplies, and http there would push every
-- employee's name and address across the network in the clear.
ALTER TABLE core.scim_targets DROP CONSTRAINT IF EXISTS scim_targets_https;

ALTER TABLE core.scim_targets
    ADD CONSTRAINT scim_targets_https CHECK (
        kind <> 'scim' OR base_url LIKE 'https://%');
