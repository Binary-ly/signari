ALTER TABLE core.clients
    ADD COLUMN exchange_requires_audience_match boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.clients.exchange_requires_audience_match IS
    'When true, this client may only exchange subject tokens it holds or is named in the audience of.';
