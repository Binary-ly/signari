-- signari:compatible-with-previous
--
-- 0229_application_roles.sql
--
-- A role in an application (11.10). A role is a relation on application:<client_id>, granted
-- as any other relation is, to a person or a group, with an expiry if it wants one. What was
-- missing is the application hearing about it: roles_claim names the claim a client's tokens
-- carry them in. NULL carries none, as every client did.

ALTER TABLE core.clients ADD COLUMN roles_claim text
    CONSTRAINT clients_roles_claim_length CHECK (length(roles_claim) BETWEEN 1 AND 128)
    CONSTRAINT clients_roles_claim_not_a_protocol_claim CHECK (roles_claim NOT IN (
        'iss','sub','aud','exp','iat','nbf','jti','azp','nonce',
        'auth_time','acr','amr','sid','at_hash','c_hash','s_hash',
        'client_id','scope','cnf'
    ));
