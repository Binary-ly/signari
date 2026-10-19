-- 0150_credential_proof_roots.sql
--
-- The roots an OID4VCI key proof's `x5c` chain must verify to.
--
-- The proof code has accepted `x5c` since it was written, verifying the chain
-- to ProofContext.TrustedX5CRoots, and the credential endpoint never filled
-- that, so every such proof was refused: there was nowhere to say which roots
-- this issuer trusts. A chain is accepted only to a root somebody registered
-- here, never on its own signature, which a self-signed certificate satisfies.
--
-- Per organisation, as attesters are: which wallet providers' hardware an
-- issuer trusts is that issuer's decision.

SET search_path = core, public;

CREATE TABLE credential_proof_roots (
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- A name for the root, because withdrawing trust in one is an act somebody
    -- has to be able to perform by name.
    name        text        NOT NULL CHECK (length(btrim(name)) > 0),
    -- DER. Public, and a trust decision rather than a secret.
    certificate bytea       NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, name)
);

ALTER TABLE credential_proof_roots ENABLE ROW LEVEL SECURITY;
ALTER TABLE credential_proof_roots FORCE ROW LEVEL SECURITY;
CREATE POLICY credential_proof_roots_org_isolation ON credential_proof_roots
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON credential_proof_roots TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER credential_proof_roots_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.credential_proof_roots
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.credential_proof_roots IS
    'OID4VCI key proofs: the roots an x5c chain must verify to. None registered means x5c is refused.';
