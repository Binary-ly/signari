-- Which RSA key transport algorithm to use when encrypting assertions.
--
-- XML Encryption's original algorithm, rsa-oaep-mgf1p, fixes SHA-1 as OAEP's
-- hash and mask generation function. That is not a signature and not a
-- collision-resistance claim -- MGF1 needs a pseudorandom function, and SHA-1
-- remains one -- so it is not broken in the way SHA-1 signatures are.
--
-- It is, however, refused outright by FIPS 140-3 modules, which do not evaluate
-- the argument. A deployment running in FIPS-only mode cannot encrypt an
-- assertion at all with mgf1p. The xmlenc11 rsa-oaep algorithm carries explicit
-- digest and MGF parameters and can therefore name SHA-256.
--
-- The default is the interoperable one, not the modern one. Every service
-- provider implements mgf1p; xmlenc11 rsa-oaep is widely but not universally
-- supported, and choosing it for a service provider that cannot read it
-- produces an assertion that decrypts nowhere. That is a decision for whoever
-- knows the far end, so it is a per-provider setting rather than a global.
ALTER TABLE core.saml_providers
    ADD COLUMN sp_key_transport text NOT NULL DEFAULT 'rsa-oaep-mgf1p'
        CHECK (sp_key_transport IN ('rsa-oaep-mgf1p', 'rsa-oaep-sha256'));

COMMENT ON COLUMN core.saml_providers.sp_key_transport IS
    'RSA key transport for encrypted assertions. rsa-oaep-mgf1p is universally '
    'supported and uses SHA-1 inside OAEP, which FIPS 140-only mode refuses. '
    'rsa-oaep-sha256 is xmlenc11 rsa-oaep with SHA-256, required for FIPS.';
