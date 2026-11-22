-- signari:compatible-with-previous
--
-- 0164_saml_signature_alg.sql
--
-- Which signature algorithm a service provider is signed with (3.15).
--
-- RSA-SHA256 by default, because it is what SAML deployments interoperate on.
-- ECDSA-SHA256 is specified and refused by a great deal of real
-- service-provider software, so choosing it for a provider that cannot verify
-- it produces assertions that are correct and rejected anyway. That is a
-- decision for whoever knows the far end, so it is per provider, like
-- sp_key_transport, rather than following whichever key is active.
--
-- Compatible with the release before: it ignores the column and signs every
-- provider with RSA, which is what this column defaults to.
ALTER TABLE core.saml_providers ADD COLUMN signature_alg text NOT NULL DEFAULT 'rsa-sha256'
    CHECK (signature_alg IN ('rsa-sha256', 'ecdsa-sha256'));

COMMENT ON COLUMN core.saml_providers.signature_alg IS
    'The XML signature algorithm this provider is signed with: rsa-sha256 by the '
    'active RS256 key, or ecdsa-sha256 by the active ES256 key. Set with '
    '`signari saml signing -signature-alg`.';
