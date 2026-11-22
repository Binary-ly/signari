-- signari:compatible-with-previous
-- 0273_client_response_encryption.sql
--
-- Signed userinfo, and encrypting an ID token, a userinfo response and an authorization
-- response to a key the client registered. Each is the client's own choice and the
-- default stays as it was: a client that asked for encryption gets it or gets nothing.

ALTER TABLE core.clients ADD COLUMN userinfo_signed_response_alg text
    CHECK (userinfo_signed_response_alg IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                                            'PS256', 'PS384', 'PS512', 'EdDSA'));
ALTER TABLE core.clients ADD COLUMN id_token_encrypted_response_alg text
    CHECK (id_token_encrypted_response_alg IN ('RSA-OAEP-256', 'ECDH-ES'));
ALTER TABLE core.clients ADD COLUMN id_token_encrypted_response_enc text
    CHECK (id_token_encrypted_response_enc IN ('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'));
ALTER TABLE core.clients ADD COLUMN userinfo_encrypted_response_alg text
    CHECK (userinfo_encrypted_response_alg IN ('RSA-OAEP-256', 'ECDH-ES'));
ALTER TABLE core.clients ADD COLUMN userinfo_encrypted_response_enc text
    CHECK (userinfo_encrypted_response_enc IN ('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'));
ALTER TABLE core.clients ADD COLUMN authorization_encrypted_response_alg text
    CHECK (authorization_encrypted_response_alg IN ('RSA-OAEP-256', 'ECDH-ES'));
ALTER TABLE core.clients ADD COLUMN authorization_encrypted_response_enc text
    CHECK (authorization_encrypted_response_enc IN ('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'));
