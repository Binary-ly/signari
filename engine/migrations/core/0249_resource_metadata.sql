-- signari:compatible-with-previous
-- 0249_resource_metadata.sql
--
-- A registered resource publishes where to get a token for it (12.15). An MCP server had to
-- publish its own RFC 9728 document to be found; now it can point its 401 at one this deployment
-- serves for it, under a handle that says nothing about the organisation. An older binary ignores
-- both columns.

ALTER TABLE core.resource_servers ADD COLUMN id uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE core.resource_servers ADD COLUMN scopes text[] NOT NULL DEFAULT '{}';

CREATE INDEX resource_servers_id ON core.resource_servers (id);
