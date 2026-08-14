-- 0029_par.sql
--
-- Pushed Authorization Requests (RFC 9126).
--
-- The client POSTs its authorization request here, authenticated, and gets back
-- an opaque handle. The browser then carries only that handle.
--
-- # What it fixes
--
-- An ordinary authorization request travels in a URL the browser can see, store
-- and forward. Every parameter is therefore visible in browser history, in
-- `Referer` headers to whatever the page loads, in reverse-proxy access logs, in
-- shoulder-surfing distance, and in whatever the user pastes into a support
-- ticket. It is also editable: nothing stops the person in the middle changing
-- `scope` before it arrives.
--
-- With PAR the parameters cross the network once, over TLS, from an
-- authenticated client -- and the browser carries an opaque handle that means
-- nothing to anybody who captures it after use.

SET search_path = core, public;

CREATE TABLE pushed_requests (
    -- Hash, not the handle. It is a credential -- whoever holds it can begin an
    -- authorization -- and this schema hashes every credential it stores.
    uri_hash    bytea       PRIMARY KEY,
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The client that pushed it. Checked again when the handle is used: a
    -- handle usable by a DIFFERENT client would let one client begin an
    -- authorization with another's registered redirect_uri.
    client_id   text        NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- The pushed parameters, verbatim. Stored rather than re-derived so that
    -- what is authorized is exactly what was pushed -- the integrity property
    -- is the point of the feature.
    params      jsonb       NOT NULL,

    created_at  timestamptz NOT NULL DEFAULT now(),
    -- Short. The handle is used immediately, by a redirect the client controls;
    -- a long window is time in which a captured handle still works.
    expires_at  timestamptz NOT NULL DEFAULT now() + interval '90 seconds',
    -- Single use. Set when consumed, so a second attempt is refused rather than
    -- silently starting a second authorization.
    used_at     timestamptz
);

CREATE INDEX pushed_requests_expiry_idx ON pushed_requests (expires_at);

ALTER TABLE pushed_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE pushed_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY pushed_requests_org_isolation ON pushed_requests
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON pushed_requests TO signari_maintenance;

-- Whether a client may ONLY start an authorization through PAR.
--
-- Off by default: turning it on breaks any integration that has not moved. On,
-- it closes the loophole that makes PAR advisory -- a client that can also send
-- a plain authorization request has not gained the integrity property, it has
-- gained an option.
ALTER TABLE clients
    ADD COLUMN require_pushed_authorization boolean NOT NULL DEFAULT false;
