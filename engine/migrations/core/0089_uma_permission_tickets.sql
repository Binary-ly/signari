
SET search_path = core, public;

CREATE TABLE uma_permission_tickets (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The resource server that asked for this ticket. It is a registered client
    -- authenticating at the permission endpoint, so the ticket can be traced to
    -- whoever created it.
    resource_server text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- SHA-256 of the ticket. Never the ticket.
    ticket_hash  bytea NOT NULL UNIQUE CHECK (length(ticket_hash) = 32),

    -- What is being asked for, as the resource server described it. A JSON array
    -- of {resource_type, resource_id, resource_scopes}, kept verbatim so the
    -- decision is made against exactly what was requested rather than against a
    -- reconstruction of it.
    permissions  jsonb NOT NULL,

    -- Single use, per 3.3.1.
    redeemed_at  timestamptz,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE uma_permission_tickets ENABLE ROW LEVEL SECURITY;
ALTER TABLE uma_permission_tickets FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_permission_tickets_org_isolation ON uma_permission_tickets
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON uma_permission_tickets TO signari_maintenance;

-- The janitor sweeps these; without an index it walks the table.
CREATE INDEX uma_permission_tickets_expiry ON uma_permission_tickets (expires_at);

COMMENT ON TABLE uma_permission_tickets IS
    'UMA 2.0 permission tickets. Single-use per section 3.3.1, hashed at rest because a ticket is a bearer credential in transit between the resource server and the client.';
