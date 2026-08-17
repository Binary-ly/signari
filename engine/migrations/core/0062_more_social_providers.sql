-- Apple, GitLab, Discord, Twitch and LinkedIn as federated sign-in providers.
--
-- The kind column carries a CHECK enumerating the providers the engine knows,
-- and the enumeration is duplicated between this constraint and the presets map
-- in internal/federation. Two lists that must agree and cannot check each other
-- is exactly how a new provider comes to work everywhere except the database --
-- which is what happened here, and is why there is now a test asserting the
-- database accepts every kind the code can produce.
ALTER TABLE core.identity_providers
    DROP CONSTRAINT IF EXISTS identity_providers_kind_check;

ALTER TABLE core.identity_providers
    ADD CONSTRAINT identity_providers_kind_check CHECK (kind = ANY (ARRAY[
        'oidc', 'google', 'github', 'microsoft', 'saml',
        'apple', 'gitlab', 'discord', 'twitch', 'linkedin'
    ]));
