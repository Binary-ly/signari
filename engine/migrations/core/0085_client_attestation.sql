-- OAuth 2.0 Attestation-Based Client Authentication,
-- draft-ietf-oauth-attestation-based-client-auth-10 (6 July 2026).
--
-- # What this buys that PKCE and DPoP do not
--
-- A public client has no secret, so anything holding its `client_id` -- a
-- repackaged app, a script, a modified build -- is indistinguishable from the
-- real one. PKCE binds a code to a one-time secret; DPoP binds a token to a key.
-- Neither says anything about WHAT holds that key.
--
-- ABCA introduces a third party, the Client Attester, which vouches that a
-- particular key belongs to a genuine instance of a known application.
--
-- # Attesters are registered, never discovered
--
-- §7.1 rule 4: the attestation's signature must verify "with the public key of a
-- known and trusted Client Attester". That word `trusted` is the whole trust
-- model. An attestation signed by a valid key nobody registered must be refused,
-- or any party capable of signing a JWT could vouch for any client -- which is
-- exactly the property ABCA exists to establish, handed away.
CREATE TABLE core.client_attesters (
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- A human name for the attester, because revoking trust in one is an
    -- operational act somebody has to be able to perform confidently.
    name        text NOT NULL,

    -- The attester's public keys, as a JWKS. Plural because an attester rotates
    -- signing keys like anyone else, and a single-key column would make rotation
    -- a flag day for every client it attests.
    jwks        jsonb NOT NULL,

    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (org_id, name)
);

-- Server-issued challenges, §6.
--
-- §7.2 rules 5 and 8 make the challenge binding when the server issued one, and
-- §6.1 goes further: "If the Authorization Server offers a challenge endpoint,
-- the Client MUST retrieve a challenge and MUST use this challenge".
--
-- Stored rather than derived, because the point is that the SERVER chose the
-- value and can therefore date it. A stateless challenge (an HMAC over a
-- timestamp) would prove freshness but not single use, and single use is what
-- makes a captured PoP worthless rather than merely short-lived.
--
-- Single use is enforced the way every other one-shot credential here is: an
-- UPDATE with the condition in the WHERE clause, so two concurrent uses cannot
-- both win.
CREATE TABLE core.attestation_challenges (
    -- The challenge is a bearer value, so only its hash is stored. Anyone
    -- reading this table must not thereby be able to answer a challenge.
    challenge_hash bytea PRIMARY KEY,
    org_id         uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    issued_at      timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz
);

CREATE INDEX attestation_challenges_expiry_idx ON core.attestation_challenges (expires_at);

COMMENT ON TABLE core.client_attesters IS
    'draft-ietf-oauth-attestation-based-client-auth-10 section 7.1 rule 4: the trusted Client Attesters whose signatures make an attestation acceptable.';
COMMENT ON TABLE core.attestation_challenges IS
    'Section 6 challenges. Hashed and single-use, so a captured PoP JWT is worthless rather than merely short-lived.';

-- `attest_jwt_client_auth` becomes a selectable client authentication method.
--
-- The CHECK from 0027 enumerates the permitted values, so adding a method to the
-- code without adding it here produces a client nobody can configure. That is
-- the right failure -- a constraint refusing an unknown method is what stops a
-- typo silently becoming "authenticates with nothing" -- but it does mean the
-- list and the dispatch have to move together.
ALTER TABLE core.clients DROP CONSTRAINT IF EXISTS clients_token_endpoint_auth_method_check;
ALTER TABLE core.clients ADD CONSTRAINT clients_token_endpoint_auth_method_check
    CHECK (token_endpoint_auth_method IN
           ('client_secret_post','client_secret_basic','private_key_jwt','none',
            'attest_jwt_client_auth'));

-- A client set to attestation-based authentication needs at least one attester
-- its organisation trusts, or it can never authenticate. Not expressible as a
-- CHECK across tables, so it is enforced at verification time with an error that
-- names the cause -- see abca.VerifyAttestation's empty-trust-set branch.
