-- 0020_saml_certificates.sql
--
-- SAML needs an X.509 certificate where OIDC needs only a public key.
--
-- Service providers pin the certificate out of our metadata and compare it on
-- every assertion. That makes it a long-lived, externally-held commitment: the
-- key rotation this project already implements is a background operation for
-- OIDC, and a COORDINATED CHANGE for SAML, because every SP has a copy.
--
-- The certificate is therefore stored rather than derived. A certificate
-- regenerated on demand would carry a new serial and new validity dates each
-- time, so its fingerprint would change, and every SP pinning it would start
-- rejecting assertions -- intermittently, depending which node answered.

SET search_path = core, public;

ALTER TABLE signing_keys
    -- DER, not PEM: the wire format for SAML metadata is base64 of DER, so
    -- storing DER avoids a parse-and-reserialise on a path that must not fail.
    ADD COLUMN certificate bytea,
    -- Recorded because it is the value operators are asked for, compare in
    -- support tickets, and see in SP configuration screens. Computing it on
    -- demand is easy; having it in the same row as the certificate is what makes
    -- "which key is this SP pinned to" answerable with one query.
    ADD COLUMN certificate_sha256 text,
    ADD COLUMN certificate_not_after timestamptz;

COMMENT ON COLUMN signing_keys.certificate IS
    'Self-signed X.509 (DER) wrapping this key, for SAML metadata. Stable: service providers pin it.';
