-- A c_nonce is not organisation data.
--
-- 0081 scoped credential nonces to an organisation, which forced the Nonce
-- Endpoint to resolve one -- and §7.1 makes that endpoint UNAUTHENTICATED, so
-- there is no subject to resolve from. The only thing available was the
-- configured issuer, which is not reliably joinable to an organisation.
--
-- The scoping bought nothing. A c_nonce establishes that a key proof is fresh
-- (§8.2); it carries no authority and identifies nobody. What decides which
-- organisation a credential is issued for is the ACCESS TOKEN's subject, checked
-- at the credential endpoint, where there genuinely is one.
--
-- So the column becomes optional and the claim no longer filters on it. Removing
-- a check is worth stating plainly: this one was not protecting anything, and
-- keeping it would have meant the unauthenticated endpoint guessing at a tenant.
ALTER TABLE core.credential_nonces ALTER COLUMN org_id DROP NOT NULL;

COMMENT ON COLUMN core.credential_nonces.org_id IS
    'Optional. A c_nonce proves freshness only; the organisation a credential is issued for comes from the access token at the credential endpoint.';
