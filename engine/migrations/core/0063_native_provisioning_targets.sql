-- Provisioning targets that are not SCIM servers.
--
-- Google Workspace and Microsoft Entra ID cannot be provisioned into over
-- SCIM. Entra is a SCIM *client* -- it pushes out, it does not accept pushes in
-- -- and Google has no SCIM surface at all. Both are written through their own
-- APIs instead: the Admin SDK Directory API and Microsoft Graph.
--
-- The reconciliation above them is unchanged, which is the point of adding a
-- kind here rather than a second sync engine. A second engine is how the
-- deactivation rule ends up meaning something slightly different for Google
-- than it does for everything else.
--
-- These connectors are the paid tier elsewhere in this field. The hard part is
-- the reconciliation, and that was already written.
ALTER TABLE core.scim_targets
    ADD COLUMN kind text NOT NULL DEFAULT 'scim'
        CHECK (kind IN ('scim', 'google', 'entra')),
    -- Sealed with the root key, like every other stored credential. A service
    -- account JSON file or an Entra client secret is a credential to somebody
    -- else's entire directory.
    ADD COLUMN credentials_enc bytea,
    -- The administrator a Google service account impersonates. Domain-wide
    -- delegation does nothing without a subject.
    ADD COLUMN impersonate text,
    -- The domain new accounts are created under.
    ADD COLUMN target_domain text;

-- A native target needs credentials; a SCIM one needs a base URL and a token.
-- Encoding that here means a half-configured target is refused at the moment it
-- is registered rather than at 3am when the sync runs.
ALTER TABLE core.scim_targets
    ADD CONSTRAINT scim_targets_configured_for_its_kind CHECK (
        (kind = 'scim'  AND base_url <> '' AND token <> '')
     OR (kind <> 'scim' AND credentials_enc IS NOT NULL));

COMMENT ON COLUMN core.scim_targets.kind IS
    'scim for a SCIM 2.0 server; google or entra for targets that must be '
    'written through their own APIs.';
