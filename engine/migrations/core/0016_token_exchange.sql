-- 0016_token_exchange.sql
--
-- RFC 8693 token exchange, off by default per client.
--
-- Token exchange turns one token into another: a different audience, a narrower
-- scope, or a token that records one party acting on behalf of another. It is
-- the primitive behind service-to-service delegation, and behind an AI agent
-- acting for a user.
--
-- It is also, structurally, a privilege-transfer mechanism, so the default is
-- off. A client that can exchange tokens it did not receive, or exchange them
-- for MORE than it was given, is not a delegation feature -- it is an escalation
-- path with an RFC number.

SET search_path = core, public;

ALTER TABLE clients
    -- May this client call the exchange grant at all?
    ADD COLUMN may_exchange boolean NOT NULL DEFAULT false,
    -- Audiences it may exchange FOR. Empty means "only its own", which is the
    -- safe default: an unrestricted exchanger can mint a token for any resource
    -- server in the deployment.
    ADD COLUMN exchange_audiences text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN clients.may_exchange IS
    'RFC 8693. Off by default: exchange transfers privilege and must be granted deliberately.';
