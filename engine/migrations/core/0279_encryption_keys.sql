-- 0279_encryption_keys.sql
--
-- A key this server decrypts with, which until now it had no need of. OpenID4VCI §8.2:
-- "Credential Request encryption MUST be used if the credential_response_encryption
-- parameter is included, to prevent it being substituted by an attacker". So a wallet
-- asking for its credential encrypted has to encrypt the asking, to a key published here.
-- Kept apart from the signing keys, as federation keys are, and for the same reason: a key
-- does one job. Not compatible with the release before, which has no idea of this purpose.

ALTER TABLE core.signing_keys DROP CONSTRAINT signing_keys_purpose_check;
ALTER TABLE core.signing_keys ADD CONSTRAINT signing_keys_purpose_check
    CHECK (purpose IN ('oidc', 'federation', 'encryption'));
