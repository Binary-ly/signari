-- RFC 9449 §5: bind a public client's refresh token to its DPoP key.
--
--	"When an authorization server supporting DPoP issues a refresh token to a
--	public client that presents a valid DPoP proof at the token endpoint, the
--	refresh token MUST be bound to the respective public key. The binding MUST
--	be validated when the refresh token is later presented to get new access
--	tokens."
--
-- Both sentences matter and only the first is obvious. The token endpoint
-- already verified a proof and put its thumbprint on the new access token's
-- `cnf` -- correct, and not the requirement. Without the binding recorded HERE,
-- a stolen refresh token is replayable by anyone: the thief presents it with
-- their OWN key, the proof verifies (it is a valid proof, of their key), and
-- they receive a fresh access token bound to themselves. Sender-constraining
-- would hold for the access token and evaporate for the credential that mints
-- new ones -- which is the longer-lived of the two.
--
-- On the FAMILY rather than the token, because §5 binds the credential across
-- rotations: "a client MUST present a DPoP proof for the same key ... each time
-- that refresh token is used". A per-token column would let the key change from
-- one rotation to the next, which is the property being denied.
--
-- Nullable, and deliberately so: this is null for every refresh token issued
-- without a DPoP proof, and those are ordinary bearer credentials. A NOT NULL
-- would mean claiming every refresh token in the system is key-bound.
ALTER TABLE core.refresh_token_families ADD COLUMN dpop_jkt text;

COMMENT ON COLUMN core.refresh_token_families.dpop_jkt IS
    'RFC 9449 §5 refresh token binding: the JWK Thumbprint the lineage is bound to. Enforced for public clients at every rotation; null when the family was not established with a DPoP proof.';
