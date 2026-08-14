-- 0017_proxy_hosts.sql
--
-- The hosts forward authentication will protect, and redirect back to.
--
-- An ALLOW-LIST, not a pattern. The check people reach for is "same registrable
-- domain as the issuer", and it is wrong: anyone who can get a hostname under
-- that domain then qualifies, and the redirect target is influenced by headers
-- the original request supplied. Registering each host explicitly is the only
-- version of this that cannot be argued around.

SET search_path = core, public;

CREATE TABLE proxy_hosts (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    -- Host and port exactly as the browser sends them, because that is what the
    -- comparison sees. "app.example.com" and "app.example.com:443" are different
    -- strings and only one of them will arrive.
    host       text        NOT NULL,
    -- Off by default, like every other capability that grants access.
    enabled    boolean     NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, host)
);

ALTER TABLE proxy_hosts ENABLE ROW LEVEL SECURITY;
ALTER TABLE proxy_hosts FORCE ROW LEVEL SECURITY;
CREATE POLICY proxy_hosts_org_isolation ON proxy_hosts
    USING (org_id = core.current_org_id())
    WITH CHECK (org_id = core.current_org_id());

GRANT SELECT ON proxy_hosts TO signari_maintenance;
