-- 0032_ssf.sql
--
-- Shared Signals Framework streams, and CAEP events.
--
-- # What this adds over back-channel logout
--
-- Back-channel logout answers one question -- "this session ended" -- at one
-- moment, to the relying parties that participated in it.
--
-- Continuous Access Evaluation is the general form: a receiver subscribes to a
-- STREAM of security events about subjects it cares about, and reacts to each.
-- Session revoked, credential changed, assurance level reduced, device
-- compliance lost. The point is that a relying party holding a token valid for
-- another twenty minutes learns immediately that it should stop honouring it,
-- instead of finding out when the token expires.
--
-- It is the same argument this project has made about logout all along, applied
-- continuously rather than once.

SET search_path = core, public;

CREATE TABLE ssf_streams (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- Which relying party this stream belongs to. Events are only ever sent
    -- about subjects that party has actually seen: a stream is not a licence to
    -- learn about every user in the directory.
    client_id    text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- Where to push Security Event Tokens (RFC 8935).
    endpoint_url text        NOT NULL,
    -- Bearer token the receiver issued us, sealed. It authenticates US to THEM.
    auth_token   bytea,

    -- Which event types this receiver asked for. An allow-list: sending an event
    -- a receiver did not ask for is at best noise and at worst a disclosure --
    -- `credential-change` tells the receiver something about the user that it
    -- may have no business knowing.
    events_requested text[]  NOT NULL DEFAULT '{}',

    status       text        NOT NULL DEFAULT 'enabled'
                             CHECK (status IN ('enabled','paused','disabled')),
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now(),

    UNIQUE (client_id),
    CONSTRAINT ssf_streams_https CHECK (endpoint_url LIKE 'https://%')
);

ALTER TABLE ssf_streams ENABLE ROW LEVEL SECURITY;
ALTER TABLE ssf_streams FORCE ROW LEVEL SECURITY;
CREATE POLICY ssf_streams_org_isolation ON ssf_streams
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON ssf_streams TO signari_maintenance;
