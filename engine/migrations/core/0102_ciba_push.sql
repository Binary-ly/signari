SET search_path = core, public;

-- CIBA push mode (Core 1.0 §7.3, §10.3).
--
-- In poll the client asks; in ping we tell it to ask; in push we send the tokens
-- themselves to its notification endpoint and the client never calls the token
-- endpoint at all -- §11: "If the Client is registered to use the Push Mode then
-- it MUST NOT call the Token Endpoint with the CIBA Grant Type".
--
-- That last sentence is why this is a third mode rather than a flag on ping: the
-- two differ in what the OP sends AND in what the client is allowed to do
-- afterwards, and a client configured for one behaving as the other is a request
-- that hangs forever or a token delivered twice.
ALTER TABLE clients DROP CONSTRAINT clients_delivery_mode_known;
ALTER TABLE clients ADD CONSTRAINT clients_delivery_mode_known
    CHECK (backchannel_token_delivery_mode = ANY (ARRAY['poll', 'ping', 'push']));

-- Both notified modes need somewhere to notify. Extended rather than duplicated:
-- expressing it as two constraints would let a row satisfy each separately.
ALTER TABLE clients DROP CONSTRAINT clients_ping_needs_an_endpoint;
ALTER TABLE clients ADD CONSTRAINT clients_ping_needs_an_endpoint
    CHECK (backchannel_token_delivery_mode NOT IN ('ping', 'push')
           OR backchannel_client_notification_endpoint IS NOT NULL);

-- §9: "It MUST be an HTTPS URL and Communication with the Client Notification
-- Endpoint MUST utilize TLS."
--
-- Enforced in the schema because push sends TOKENS there. A plaintext endpoint is
-- not a degraded configuration for this mode, it is handing an access token and a
-- refresh token to whatever is on the network path -- and the failure is silent,
-- because delivery succeeds.
--
-- Applied to ping as well: ping carries only an auth_req_id, but §9 does not
-- distinguish, and a rule that holds for one mode and not the other is one nobody
-- can remember which way round.
ALTER TABLE clients ADD CONSTRAINT clients_notification_endpoint_is_https
    CHECK (backchannel_client_notification_endpoint IS NULL
           OR backchannel_client_notification_endpoint LIKE 'https://%');

COMMENT ON COLUMN clients.backchannel_token_delivery_mode IS
    'CIBA Core 1.0 §7.3: poll, ping or push. In push the OP sends the tokens to '
    'the notification endpoint and the client MUST NOT call the token endpoint.';
