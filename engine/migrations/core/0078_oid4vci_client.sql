-- Bind a pre-authorized code to the client it was issued for.
--
-- OID4VCI §6.1: "For the Pre-Authorized Code Grant Type, authentication of the
-- Client is OPTIONAL... and, as a consequence, the client_id parameter is only
-- needed when a form of Client Authentication that relies on this parameter is
-- used."
--
-- So a conformant wallet may redeem a pre-authorized code sending NO client_id
-- at all. Our token endpoint resolves a client before it dispatches on the grant
-- type, which would have refused every such request as `invalid_client` -- and
-- the anonymous case is the ordinary one for wallets.
--
-- The fix is not to mint tokens for nobody. A token has to carry an audience,
-- scopes and a lifetime, and those are properties of a client. So the client is
-- chosen when the offer is MINTED, by the operator who knows which credential
-- issuer this offer is for, and recorded here. At redemption it is read from
-- this column rather than from the request -- which is also the stronger
-- position: the wallet cannot choose which client's scopes its token carries.
--
-- A request that DOES send a client_id must match, because a wallet naming a
-- different client than the offer was issued to means the two disagree about
-- what is being redeemed.
ALTER TABLE core.preauthorized_codes
    ADD COLUMN client_id text REFERENCES core.clients(client_id) ON DELETE CASCADE;

-- Nullable for the rows that predate this column; there are none in any
-- deployment, since the grant was never reachable before it. New rows are
-- required to carry one, enforced in the insert rather than by a NOT NULL that
-- would fail on a table this migration cannot backfill.
COMMENT ON COLUMN core.preauthorized_codes.client_id IS
    'The client whose scopes and token lifetimes a redemption of this code uses. Chosen at issue time because OID4VCI 6.1 lets the wallet omit client_id entirely.';
