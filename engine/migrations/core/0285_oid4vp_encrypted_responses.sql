-- signari:compatible-with-previous
-- 0285_oid4vp_encrypted_responses.sql
--
-- A wallet sign-in may ask for its answer encrypted (direct_post.jwt, OID4VP 1.0 §8.3.1), so
-- the credential crosses the wallet's network as ciphertext. Each request has a key of its
-- own, a P-256 key for ECDH-ES made when the sign-in starts, kept with the pending sign-in
-- sealed under the root key and gone with it.

ALTER TABLE core.vp_verifiers ADD COLUMN response_mode text NOT NULL DEFAULT 'direct_post'
    CHECK (response_mode IN ('direct_post', 'direct_post.jwt'));

ALTER TABLE core.federated_logins ADD COLUMN vp_response_key bytea;
