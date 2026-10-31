-- 0228_generic_oauth2.sql
--
-- A sign-in provider that speaks plain OAuth 2.0 (8.15). There is no ID token to verify and
-- no discovery document, so an operator names its three endpoints and says where in its
-- userinfo answer the person is: userinfo_subject is the one that matters, the identifier a
-- person is linked by, and it defaults to `sub`. The other three default to nothing asked
-- of the provider beyond an `email` and a `name`, and an address is not believed verified
-- unless userinfo_email_verified names where the provider says so and the operator has
-- chosen to trust it.

ALTER TABLE core.identity_providers DROP CONSTRAINT identity_providers_kind_check;
ALTER TABLE core.identity_providers ADD CONSTRAINT identity_providers_kind_check
    CHECK (kind = ANY (ARRAY['oidc', 'oauth2', 'google', 'github', 'microsoft', 'saml',
                             'apple', 'gitlab', 'discord', 'twitch', 'linkedin',
                             'slack', 'atlassian', 'assertion']));

ALTER TABLE core.identity_providers ADD COLUMN userinfo_subject text NOT NULL DEFAULT 'sub';
ALTER TABLE core.identity_providers ADD COLUMN userinfo_email text NOT NULL DEFAULT 'email';
ALTER TABLE core.identity_providers ADD COLUMN userinfo_email_verified text NOT NULL DEFAULT '';
ALTER TABLE core.identity_providers ADD COLUMN userinfo_name text NOT NULL DEFAULT 'name';

ALTER TABLE core.identity_providers ADD CONSTRAINT identity_providers_oauth2_endpoints
    CHECK (kind <> 'oauth2' OR (authorize_url LIKE 'https://%' AND token_url LIKE 'https://%'
                                AND userinfo_url LIKE 'https://%'));
