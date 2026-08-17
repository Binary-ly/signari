-- Slack and Atlassian as federated sign-in providers.
--
-- Both endpoints sets were read from those providers' own
-- /.well-known/openid-configuration rather than from documentation.
--
-- Facebook was considered and NOT added: its discovery document omits the token
-- endpoint, and this project's rule is that a preset's endpoints come from the
-- provider's own document. A preset built from a remembered endpoint looks
-- configured and fails when somebody tries to sign in, which is worse than not
-- offering it. Use the generic `oidc` kind with endpoints you have checked.
ALTER TABLE core.identity_providers
    DROP CONSTRAINT IF EXISTS identity_providers_kind_check;

ALTER TABLE core.identity_providers
    ADD CONSTRAINT identity_providers_kind_check CHECK (kind = ANY (ARRAY[
        'oidc', 'google', 'github', 'microsoft', 'saml',
        'apple', 'gitlab', 'discord', 'twitch', 'linkedin',
        'slack', 'atlassian'
    ]));
