-- A million people for a benchmark database, written straight in as a superuser: 1,000
-- organisations of 1,000 people (bench-N@bench.invalid), one session each, and ten audit events
-- each. Every person gets the password hash of template@bench.invalid, which must exist, as
-- `bench seed` does. The audit rows carry random hashes: they are volume for the tables and
-- indexes every request and sweep reads past, not a chain `signari audit verify` would pass.
-- Never run this against a database anyone signs in to.
\set ON_ERROR_STOP on
\timing on
BEGIN;
INSERT INTO core.organizations (instance_id, slug, display_name)
SELECT (SELECT id FROM core.instances LIMIT 1), 'scale-' || g, 'Scale ' || g
  FROM generate_series(1, 1000) g;
COMMIT;

BEGIN;
INSERT INTO core.users (org_id, email, user_handle)
SELECT o.id, 'bench-' || g || '@bench.invalid', decode(md5(random()::text) || md5(random()::text), 'hex')
  FROM core.organizations o CROSS JOIN generate_series(1, 1000) g
 WHERE o.slug LIKE 'scale-%';
INSERT INTO core.password_credentials (user_id, org_id, hash, algorithm)
SELECT u.id, u.org_id, t.hash, t.algorithm
  FROM core.users u
  JOIN core.organizations o ON o.id = u.org_id AND o.slug LIKE 'scale-%'
 CROSS JOIN (SELECT p.hash, p.algorithm FROM core.users tu JOIN core.password_credentials p ON p.user_id = tu.id
              WHERE tu.email = 'template@bench.invalid') t;
COMMIT;

BEGIN;
INSERT INTO core.sessions (sid, org_id, user_id, auth_time, not_after, absolute_not_after, last_seen_at)
SELECT encode(sha256((random()::text || u.id::text)::bytea), 'hex'), u.org_id, u.id, now(),
       now() + interval '12 hours', now() + interval '12 hours', now()
  FROM core.users u JOIN core.organizations o ON o.id = u.org_id AND o.slug LIKE 'scale-%';
COMMIT;

BEGIN;
INSERT INTO core.audit_events (org_id, occurred_at, event_type, subject_id, detail, prev_hash, entry_hash, hash_version)
SELECT u.org_id, now() - (g * interval '1 second'), 'session.created', u.id, '{}'::jsonb,
       sha256(random()::text::bytea), sha256(random()::text::bytea), 2
  FROM generate_series(1, 10) g
 CROSS JOIN core.users u JOIN core.organizations o ON o.id = u.org_id AND o.slug LIKE 'scale-%';
COMMIT;

ANALYZE;
SELECT (SELECT count(*) FROM core.organizations) AS organisations, (SELECT count(*) FROM core.users) AS people,
       (SELECT count(*) FROM core.sessions) AS sessions, (SELECT count(*) FROM core.audit_events) AS audit_events,
       pg_size_pretty(pg_database_size(current_database())) AS size;
