-- signari:compatible-with-previous
--
-- 0216_idp_token_auth.sql
--
-- How this engine proves itself at an upstream provider's token endpoint (8.16). It
-- sent a client secret in the form and could do nothing else, so a provider set up
-- with a certificate and no secret, which a good many are as a matter of policy,
-- could not be used at all.
--
-- client_key is the private key sealed under the root key, and is classified in
-- internal/keys with the client secret. client_certificate is public, and a
-- provider that identifies a key by its certificate needs it named in the assertion.

ALTER TABLE core.identity_providers ADD COLUMN token_auth_method text NOT NULL DEFAULT 'client_secret_post';
ALTER TABLE core.identity_providers ADD COLUMN client_key bytea;
ALTER TABLE core.identity_providers ADD COLUMN client_certificate text;
