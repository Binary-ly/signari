-- signari:compatible-with-previous
-- 0248_ssf_source_poll.sql
--
-- Pulling a transmitter's events rather than waiting to be sent them (12.04). RFC 8936's other
-- half: this deployment has been able to be polled, and could not poll. A receiver behind a
-- firewall, or a transmitter that only offers polling, had no way to meet. The credential is the
-- transmitter's to give, so it is sealed under the root key; a client id means it is sent as Basic
-- and none means a bearer token. An older binary ignores the columns and polls nothing.

ALTER TABLE core.ssf_sources ADD COLUMN poll_url text CHECK (poll_url LIKE 'https://%');
ALTER TABLE core.ssf_sources ADD COLUMN poll_client_id text;
ALTER TABLE core.ssf_sources ADD COLUMN poll_secret_sealed bytea;
ALTER TABLE core.ssf_sources ADD COLUMN next_poll_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE core.ssf_sources ADD COLUMN last_polled_at timestamptz;
ALTER TABLE core.ssf_sources ADD COLUMN last_poll_error text;

CREATE INDEX ssf_sources_due ON core.ssf_sources (next_poll_at) WHERE enabled AND poll_url IS NOT NULL;
