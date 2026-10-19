-- 0153_credential_nonce_unscoped.sql
--
-- A c_nonce belongs to no organisation, so the column that said otherwise goes.
--
-- 0082 made credential_nonces.org_id optional because the Nonce Endpoint is
-- unauthenticated and has no tenant to resolve, and a c_nonce proves only that
-- a key proof is fresh; the organisation a credential is issued for comes from
-- the access token at the credential endpoint. Nothing has written the column
-- since. Keeping it left an org-isolation policy filtering on a value that is
-- always NULL, and a column a reader would take for a scope that does not exist.
--
-- The policy is replaced, not just dropped: the table FORCEs row-level
-- security, and with no policy at all every role, the engine included, would
-- see nothing. The engine alone reads and writes nonces.

SET search_path = core, public;

DROP POLICY credential_nonces_org_isolation ON core.credential_nonces;
ALTER TABLE core.credential_nonces DROP COLUMN org_id;
CREATE POLICY credential_nonces_engine_only ON core.credential_nonces
    USING (core.is_engine())
    WITH CHECK (core.is_engine());
