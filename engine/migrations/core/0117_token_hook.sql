-- A provider consulted while a token is being minted.
--
-- # What it may do, and why the list is this short
--
-- The existing `authorize` hook is VETO-ONLY: consulted after a local allow, it
-- can deny and nothing else. That composition is the whole reason it is safe to
-- hand an operator an out-of-process extension point at all — a provider that
-- could grant would let an external service overrule this engine's own
-- decisions, and a compromised or merely wrong provider would widen access
-- rather than narrow it.
--
-- The token hook keeps that discipline and adds exactly one capability:
--
--   1. VETO issuance, with a reason.
--   2. Contribute claims, from a list the OPERATOR declared at registration.
--
-- It may not widen scope, change the audience, extend a lifetime, or write any
-- claim the protocol defines. Those are all ways an extension could turn into an
-- authorization decision made somewhere this deployment does not control.
--
-- # Why the allow-list is on the PROVIDER, not in the provider's response
--
-- Because the question "what may this external service put in my users' tokens"
-- is the operator's, and an answer that travelled in the provider's own response
-- would be the provider answering it. Registering the provider is where consent
-- to trust it lives, so the bound is recorded there.
--
-- An empty list means the provider may contribute nothing and is consulted only
-- for its veto, which is a legitimate and probably common configuration.

ALTER TABLE core.providers
    ADD COLUMN allowed_claims text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN core.providers.allowed_claims IS
    'Claim names this provider may contribute to a token. Empty means veto-only. '
    'Protocol claims can never be contributed regardless of what is listed here.';

-- Protocol claims are refused at registration, not merely at merge time.
--
-- Refusing here means an operator finds out when they register the provider
-- rather than never — a name that would be silently dropped at every token mint
-- is a configuration that reads as working and does nothing.
--
-- `sub` is the one that matters most: a provider that could set it would issue
-- tokens impersonating any subject at every relying party trusting this issuer.
ALTER TABLE core.providers ADD CONSTRAINT providers_claims_are_not_protocol_claims
    CHECK (NOT (allowed_claims && ARRAY[
        'iss','sub','aud','exp','iat','nbf','jti','azp','nonce',
        'auth_time','acr','amr','sid','at_hash','c_hash','s_hash',
        'client_id','scope','cnf'
    ]::text[]));
