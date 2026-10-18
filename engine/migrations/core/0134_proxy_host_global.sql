-- 0134_proxy_host_global.sql
--
-- A forward-auth protected host belongs to one organisation in the whole
-- deployment.
--
-- # The defect
--
-- proxy_hosts was UNIQUE (org_id, host), and the verify endpoint admitted a
-- request when the signed-in person's organisation had registered the host the
-- proxy named. Every writer -- the Admin API, the CLI and `signari apply` --
-- accepted a host another organisation already held. So a second tenant's
-- administrator registered the first tenant's payroll host, and every one of
-- the second tenant's people passed the first tenant's proxy, with whatever
-- address the second tenant had given them in the identity headers.
--
-- # Why unique rather than checked at verify
--
-- A host is reached by one reverse proxy in front of one application; it is
-- not a name two tenants can each mean something by. As 0129 and 0130, the
-- second registration is refused where it is made.
--
-- Compared case-insensitively, because DNS is: a host registered with capitals
-- would otherwise be a second registration of the same name.
--
-- # Why the migration refuses rather than chooses
--
-- Which tenant keeps a host held by two is the operator's decision, and one of
-- them has been admitting the other's people.

SET search_path = core, public;

DO $$
DECLARE
    duplicates text;
BEGIN
    SELECT string_agg(format('%s (organisations %s)', h, orgs), '; ')
      INTO duplicates
      FROM (SELECT lower(host) AS h, string_agg(org_id::text, ', ' ORDER BY created_at) AS orgs
              FROM core.proxy_hosts
             GROUP BY lower(host)
            HAVING count(*) > 1) d;
    IF duplicates IS NOT NULL THEN
        RAISE EXCEPTION 'forward-auth protected hosts must be unique across organisations, '
            'because the verify endpoint admits whoever''s organisation registered the host; '
            'these are registered by more than one: %', duplicates
            USING HINT = 'Remove all but the rightful owner''s registration of each, and run '
                'the migration again.';
    END IF;
END $$;

-- The per-organisation constraint stays: `signari apply` upserts on it.
CREATE UNIQUE INDEX proxy_hosts_host_key ON core.proxy_hosts (lower(host));
