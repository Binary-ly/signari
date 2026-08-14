-- 0026_dpop.sql
--
-- Replay detection for DPoP proofs (RFC 9449 §11.1).
--
-- A proof is signed, fresh and bound to a method, URI and access token -- and
-- still replayable within its lifetime by anyone who captures it in transit or
-- reads it out of a proxy log. The jti is what makes a second use detectable,
-- and detection needs somewhere to remember.
--
-- Separate from revoked_jtis, which holds tokens WE issued and revoked. These
-- are identifiers a client chose, so the two must not share a namespace: a
-- client that could write into the revocation list by choosing a jti could
-- revoke somebody else's token.

SET search_path = core, public;

CREATE TABLE dpop_seen_jtis (
    -- The jti alone is not the key. Two clients may legitimately pick the same
    -- one, and a shared namespace would let either deny service to the other by
    -- burning identifiers.
    jkt        text        NOT NULL,
    jti        text        NOT NULL,
    seen_at    timestamptz NOT NULL DEFAULT now(),
    -- Swept by the janitor. Retained past the proof's own age limit so a replay
    -- cannot wait out the record.
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (jkt, jti)
);

CREATE INDEX dpop_seen_jtis_expiry_idx ON dpop_seen_jtis (expires_at);

-- No RLS: this table holds no tenant data and no identity. It is a set of
-- opaque strings whose only purpose is to have been seen before, and scoping it
-- per organisation would mean the same proof could be replayed once per tenant.
GRANT SELECT ON dpop_seen_jtis TO signari_maintenance;
