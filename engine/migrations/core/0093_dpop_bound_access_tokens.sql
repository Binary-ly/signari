-- RFC 9449 §5.2 client registration metadata.
--
--   "dpop_bound_access_tokens: A boolean value specifying whether the client
--    always uses DPoP for token requests. If omitted, the default value is
--    false. If the value is true, the authorization server MUST reject token
--    requests from the client that do not contain the DPoP header."
--
-- This is how a client pins itself to DPoP. Without it, a client that intends
-- to be sender-constrained on every request has no way to make the server
-- enforce that intention: a single token request that simply omits the DPoP
-- header yields an ordinary bearer token, and nothing anywhere objects. The
-- downgrade needs no attack on DPoP itself -- only the absence of the proof.
--
-- Defaults to false because §5.2 says it does, and because any other default
-- would refuse every existing client's next token request.
ALTER TABLE core.clients
    ADD COLUMN dpop_bound_access_tokens boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.clients.dpop_bound_access_tokens IS
    'RFC 9449 §5.2: when true, token requests from this client without a DPoP header are refused.';
