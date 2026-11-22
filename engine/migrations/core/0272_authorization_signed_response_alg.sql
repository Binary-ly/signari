-- signari:compatible-with-previous
-- 0272_authorization_signed_response_alg.sql
--
-- What signs a client's authorization responses (JARM §3), and with one set, a client
-- held to asking for them signed. A response a client only hopes is signed is one
-- anybody between the browser and the client can send it unsigned.

ALTER TABLE core.clients ADD COLUMN authorization_signed_response_alg text
    CHECK (authorization_signed_response_alg IN ('ES256', 'ES384', 'ES512', 'RS256', 'RS384', 'RS512',
                                                 'PS256', 'PS384', 'PS512', 'EdDSA'));
