-- signari:compatible-with-previous
--
-- 0238_saml_metadata_origin.sql
--
-- Where a SAML partner's details were read from (8.01), so that an operator can ask for them
-- again and be held to the same terms: the URL, the certificate the document has to be signed
-- with, and when it was last read. All three are empty for a partner typed in by hand. A
-- refresh is something an operator does, not something a timer does: a partner's metadata
-- says where assertions go, and that should not change while nobody is looking.

ALTER TABLE core.saml_providers ADD COLUMN metadata_url text;
ALTER TABLE core.saml_providers ADD COLUMN metadata_signer text;
ALTER TABLE core.saml_providers ADD COLUMN metadata_read_at timestamptz;

ALTER TABLE core.saml_sources ADD COLUMN metadata_url text;
ALTER TABLE core.saml_sources ADD COLUMN metadata_signer text;
ALTER TABLE core.saml_sources ADD COLUMN metadata_read_at timestamptz;
