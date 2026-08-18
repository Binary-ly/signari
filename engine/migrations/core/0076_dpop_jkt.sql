-- RFC 9449 §10: Authorization Code Binding to a DPoP Key.
--
-- The `dpop_jkt` authorization request parameter carries the JWK Thumbprint of
-- the client's proof-of-possession key. At the token endpoint the server
-- recomputes the thumbprint from the DPoP proof and, per §10, "verifies that it
-- matches the dpop_jkt parameter value in the authorization request. If they do
-- not match, it MUST reject the request."
--
-- # What this buys that PKCE does not
--
-- PKCE binds the code to a secret the client generated. dpop_jkt binds it to the
-- KEY the resulting token will be bound to, which closes the flow end to end: an
-- authorization code intercepted in the front channel cannot be redeemed by an
-- attacker's DPoP key, because the code names the key that may redeem it.
--
-- §10 notes the two are complementary and that dpop_jkt "only provides similar
-- protections when a unique DPoP key is used for each authorization request".
--
-- Nullable: the parameter is OPTIONAL (§10), and a code issued without one is
-- redeemable by any correctly-proofed key, as before.
ALTER TABLE core.authorization_codes
    ADD COLUMN dpop_jkt text;

-- Pushed authorization requests carry it too, so it survives from the push to
-- the authorization request that redeems the request_uri.
--
-- §10.1 makes this a MUST for any server supporting both PAR and DPoP: "Both
-- mechanisms MUST be supported by an authorization server that supports PAR and
-- DPoP" -- the `dpop_jkt` body parameter, and a DPoP header on the PAR request
-- treated as if dpop_jkt had been supplied.
ALTER TABLE core.pushed_requests
    ADD COLUMN dpop_jkt text;
