-- A cursor for streaming the audit trail off the box.
--
-- The audit chain is strong internally -- hash-linked, verifiable, crypto-shred
-- resistant -- and it never left the database. If the machine is breached, the
-- evidence and the thing being investigated share a blast radius, which is what
-- OWASP ASVS V16.4.3 exists to prevent: "logs are securely transmitted to a
-- logically separate system for analysis, detection, alerting, and escalation."
--
-- Streaming forwards each new event to a syslog collector or a webhook (a SIEM's
-- HTTP endpoint) as it is written. This table remembers how far the forwarder has
-- got, so a restart resumes rather than replaying from the beginning or skipping
-- what was in flight. `audit_events.id` is a bigint sequence, so "everything with
-- id > last_id" is the exact set not yet sent.
--
-- One row, enforced by the primary key on a constant. The forwarder is a
-- singleton (like the janitor), so there is one cursor, and a table that can hold
-- only one row makes that structural rather than a convention.
CREATE TABLE core.audit_stream_state (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    last_id  bigint  NOT NULL DEFAULT 0,
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO core.audit_stream_state (only_row, last_id) VALUES (true, 0);
