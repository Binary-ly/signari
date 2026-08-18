-- OpenID for Verifiable Credential Issuance 1.0 (Final, 16 September 2025):
-- the Pre-Authorized Code grant.
--
-- # Why this is the authorization server's half
--
-- OID4VCI separates two roles. The Credential Issuer holds the credential
-- endpoint and knows how to mint an SD-JWT VC or an mdoc; the Authorization
-- Server issues the access token the credential endpoint will accept. Signari is
-- the second. Its whole contribution to OID4VCI is this grant.
--
-- # What makes this grant unusual
--
-- §6.1: "For the Pre-Authorized Code Grant Type, authentication of the Client is
-- OPTIONAL". So the pre-authorized code IS the credential -- whoever presents it
-- gets a token. Two things carry the weight the client secret usually would:
--
--   * the code "MUST be short lived and single use" (§3.5), and
--   * the optional Transaction Code, whose purpose §3.5 states plainly: "to bind
--     the Pre-Authorized Code to a certain transaction to prevent replay of this
--     code by an attacker that, for example, scanned the QR code while standing
--     behind the legitimate End-User".
--
-- A pre-authorized code is typically delivered in a QR code on a screen. The
-- threat model is somebody photographing it over a shoulder, which is why the
-- transaction code travels by a different channel.
CREATE TABLE core.preauthorized_codes (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- Hashed, never stored in the clear. The same reasoning as authorization
    -- codes: read access to this table must not be read access to live
    -- credentials, and this code is a bearer credential by design.
    code_hash   bytea NOT NULL UNIQUE,

    -- Who the credential is about, and what it is for.
    user_id     uuid NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    -- The credential configuration identifiers this code authorises, as they
    -- appear in the Credential Issuer's metadata.
    configuration_ids text[] NOT NULL CHECK (cardinality(configuration_ids) > 0),

    -- The Transaction Code, hashed, when the offer declared one.
    --
    -- NULL means the offer carried no tx_code object and the token request must
    -- not send one. An empty tx_code object in an offer still REQUIRES a value
    -- in the token request (§3.5: "even if the object was empty"), so the
    -- distinction between "no transaction code" and "a transaction code that
    -- happens to be short" has to survive into storage.
    tx_code_hash bytea,
    tx_code_input_mode text CHECK (tx_code_input_mode IN ('numeric', 'text')),
    tx_code_length int CHECK (tx_code_length IS NULL OR tx_code_length BETWEEN 1 AND 64),
    tx_code_description text,

    -- Failed transaction-code attempts against THIS code.
    --
    -- A transaction code is short and user-entered, so it is guessable in the
    -- same way a device user code is. The device flow's limit is per-address,
    -- which is right for a code space shared by everyone; this one is per-code,
    -- because each pre-authorized code has its own transaction code and a
    -- guesser is attacking one offer rather than the space.
    tx_attempts int NOT NULL DEFAULT 0,

    expires_at  timestamptz NOT NULL,
    redeemed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX preauthorized_codes_expiry_idx ON core.preauthorized_codes (expires_at);

COMMENT ON TABLE core.preauthorized_codes IS
    'OID4VCI 1.0 §3.5 pre-authorized codes. Short-lived, single-use, and the sole credential for the grant.';
