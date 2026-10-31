-- 0227_signing_algorithms.sql
--
-- The 384 and 512 families (9.04). A relying party or a policy that asks for ES384, ES512,
-- RS384, RS512, PS384 or PS512 can now be given it, with the curve each ES algorithm names
-- pinned in internal/keys. Nothing signs with one until an operator publishes a key for it,
-- and a client is refused one its instance does not hold.

ALTER TABLE core.signing_keys DROP CONSTRAINT signing_keys_algorithm_check;
ALTER TABLE core.signing_keys ADD CONSTRAINT signing_keys_algorithm_check
    CHECK (algorithm IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                         'PS256', 'PS384', 'PS512', 'EdDSA'));

ALTER TABLE core.clients DROP CONSTRAINT clients_id_token_signed_alg_check;
ALTER TABLE core.clients ADD CONSTRAINT clients_id_token_signed_alg_check
    CHECK (id_token_signed_alg IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                                   'PS256', 'PS384', 'PS512', 'EdDSA'));

-- What signs the client's access tokens, for a resource server that takes something else
-- than the application reading the ID token. NULL is what signs the ID token.
ALTER TABLE core.clients ADD COLUMN access_token_signed_alg text
    CHECK (access_token_signed_alg IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                                       'PS256', 'PS384', 'PS512', 'EdDSA'));
