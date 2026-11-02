-- signari:compatible-with-previous
-- 0274_introspection_responses.sql
--
-- What signs a client's introspection responses when it asks for a JWT (RFC 9701), and
-- what they are encrypted to it with. A resource server keeps what it was told, and
-- an answer in plain JSON proves nothing to anybody it shows that to afterwards.

ALTER TABLE core.clients ADD COLUMN introspection_signed_response_alg text
    CHECK (introspection_signed_response_alg IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                                                 'PS256', 'PS384', 'PS512', 'EdDSA'));
ALTER TABLE core.clients ADD COLUMN introspection_encrypted_response_alg text
    CHECK (introspection_encrypted_response_alg IN ('RSA-OAEP-256', 'ECDH-ES'));
ALTER TABLE core.clients ADD COLUMN introspection_encrypted_response_enc text
    CHECK (introspection_encrypted_response_enc IN ('A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'));
