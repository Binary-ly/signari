-- 0151_credential_requires_key_attestation.sql
--
-- Whether a credential is issued only on a key proof a trusted attester vouches
-- for (OID4VCI 1.0 Appendix D).
--
-- The issuer metadata member that says so, key_attestations_required, "MUST NOT
-- be present" when the issuer does not require one (specs/oid4vci.txt:2429).
-- So it can be advertised only for a configuration that enforces it, and this
-- is the setting that does: the credential endpoint refuses an unattested proof
-- for a configuration that has it, and the metadata names it for exactly those.

SET search_path = core, public;

ALTER TABLE credential_configurations
    ADD COLUMN require_key_attestation boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.credential_configurations.require_key_attestation IS
    'Issued only on a key proof whose key a trusted attester vouches for; advertised as key_attestations_required.';
