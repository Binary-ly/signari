-- 0027_private_key_jwt.sql
--
-- Client authentication with a signed assertion instead of a shared secret
-- (OIDC Core §9, RFC 7523).
--
-- # Why it is better than a secret
--
-- A client secret is a symmetric credential: both sides hold it, so either side
-- leaking it is total. It crosses the network on every token request, sits in
-- environment variables, appears in `docker inspect`, and gets pasted into
-- support tickets. Rotating it is a coordinated change on both sides.
--
-- With private_key_jwt the private half never leaves the client. We hold only a
-- public key, so our database leaking discloses nothing that lets anybody
-- authenticate as that client -- which is not true of a hash we could brute
-- force offline, and certainly not of the plaintext some products still store.

SET search_path = core, public;

ALTER TABLE clients
    -- How this client authenticates at the token endpoint. Recorded rather than
    -- inferred: a client configured for private_key_jwt that also holds a stale
    -- secret must not be able to fall back to the weaker method, which is
    -- exactly the downgrade an attacker who obtained the old secret would try.
    ADD COLUMN token_endpoint_auth_method text NOT NULL DEFAULT 'client_secret_post'
        CHECK (token_endpoint_auth_method IN
               ('client_secret_post','client_secret_basic','private_key_jwt','none')),

    -- The client's public keys, as a JWKS document. Inline rather than by URL,
    -- deliberately: a jwks_uri means this server fetches an attacker-influenced
    -- URL on the authentication path, which is a request-forgery primitive and a
    -- hard dependency on somebody else's uptime during login.
    ADD COLUMN jwks jsonb;

-- A client claiming private_key_jwt with no keys can never authenticate. Better
-- to refuse the configuration than to leave one that fails at first use.
ALTER TABLE clients ADD CONSTRAINT clients_private_key_jwt_needs_keys
    CHECK (token_endpoint_auth_method <> 'private_key_jwt' OR jwks IS NOT NULL);

COMMENT ON COLUMN clients.jwks IS
    'Public JWKS for private_key_jwt. Public keys only -- nothing here authenticates anybody if disclosed.';
