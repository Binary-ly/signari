-- 0302_vp_mdoc.sql
--
-- A wallet sign-in may ask for an ISO mdoc rather than an SD-JWT VC (vp_verifiers.format
-- mso_mdoc): one document type (doctype, OID4VP B.2.3's doctype_value) and the IACA
-- certificates its document signers have to lead to (iaca_roots, PEM), as ISO/IEC 18013-5
-- 9.3.3 has a reader hold them. An mdoc names no vct, and an SD-JWT VC no doctype or IACA,
-- so each format's columns are present exactly when it is the format. Not compatible with
-- the previous release: it would read an mdoc sign-in as an SD-JWT one asking for no type.

ALTER TABLE core.vp_verifiers
    ADD COLUMN format text NOT NULL DEFAULT 'dc+sd-jwt' CHECK (format IN ('dc+sd-jwt', 'mso_mdoc'));

ALTER TABLE core.vp_verifiers ADD COLUMN doctype text;

ALTER TABLE core.vp_verifiers ADD COLUMN iaca_roots text;

ALTER TABLE core.vp_verifiers DROP CONSTRAINT vp_verifiers_vct_values_check;

ALTER TABLE core.vp_verifiers ADD CONSTRAINT vp_verifiers_format_shape CHECK (
    (format = 'dc+sd-jwt' AND cardinality(vct_values) > 0 AND doctype IS NULL AND iaca_roots IS NULL)
    OR (format = 'mso_mdoc' AND cardinality(vct_values) = 0 AND doctype <> '' AND iaca_roots <> ''));

COMMENT ON COLUMN core.vp_verifiers.format IS
    'the credential format asked for: dc+sd-jwt, or mso_mdoc for an ISO mdoc';
COMMENT ON COLUMN core.vp_verifiers.doctype IS
    'the one mdoc document type accepted (OID4VP doctype_value); NULL for an SD-JWT VC';
COMMENT ON COLUMN core.vp_verifiers.iaca_roots IS
    'PEM: the IACA certificates an mdoc''s document signer must lead to; NULL for an SD-JWT VC';
