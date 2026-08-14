-- 0028_confidential_client_credential.sql
--
-- A confidential client must hold SOME credential. Until now that meant a
-- secret, because a secret was the only kind there was.
--
-- private_key_jwt breaks that assumption in the right direction: such a client
-- has no secret at all, deliberately -- keeping one would leave a working
-- credential behind after moving away from it, which is the exact thing the
-- move was meant to end.
--
-- So the rule becomes "some credential", not "a secret". Stated as a constraint
-- rather than left to application code, because a confidential client with no
-- way to authenticate is a client that fails at first use, and the database is
-- where that can be made impossible rather than merely unlikely.

SET search_path = core, public;

ALTER TABLE clients DROP CONSTRAINT IF EXISTS clients_confidential_has_secret;

ALTER TABLE clients ADD CONSTRAINT clients_confidential_has_a_credential CHECK (
    client_type = 'public'
    OR client_secret_hash IS NOT NULL
    OR (token_endpoint_auth_method = 'private_key_jwt' AND jwks IS NOT NULL)
    -- `none` is a deliberate choice for a client that authenticates some other
    -- way entirely; it is in the method CHECK, so choosing it is explicit.
    OR token_endpoint_auth_method = 'none'
);
