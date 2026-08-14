-- SAML assertion encryption.
--
-- A separate certificate from sp_signing_cert, deliberately. A service provider
-- signs with one key and decrypts with another, and conflating them means a
-- provider that rotates its signing key silently loses the ability to decrypt --
-- or, worse, that we encrypt to a key held somewhere it was never meant to be.
-- The two appear in SAML metadata as separate KeyDescriptors with use="signing"
-- and use="encryption" for exactly this reason.
--
-- Nullable: encryption is opt-in per provider. Transport is TLS either way, and
-- a provider that has not supplied a certificate must keep working rather than
-- start failing.
ALTER TABLE core.saml_providers
    ADD COLUMN sp_encryption_cert text;

COMMENT ON COLUMN core.saml_providers.sp_encryption_cert IS
    'PEM certificate the assertion is encrypted to. Separate from sp_signing_cert: '
    'service providers use different keys to sign and to decrypt. NULL means the '
    'assertion is sent in the clear inside TLS.';
