-- 0001_bootstrap.sql
-- Roles, schemas, and the privilege boundary between the Go engine and the Laravel admin.
--
-- The boundary is enforced by GRANT/REVOKE, not by code review. See docs/adr/README.md ADR-004.
-- Run this as a superuser once per database. Everything after 0001 runs as signari_engine.

-- ---------------------------------------------------------------------------
-- Roles
-- ---------------------------------------------------------------------------
-- signari_engine : owns schema `core`. The Go protocol engine. Full DDL + DML.
-- signari_admin  : owns schema `admin`. The Laravel admin. NO access to `core` tables.
--              Reads engine data only through the versioned `core_v1` views.
--
-- Passwords are set out-of-band (env/secret manager), never in migrations.

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'signari_engine') THEN
        CREATE ROLE signari_engine LOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'signari_admin') THEN
        CREATE ROLE signari_admin LOGIN;
    END IF;
    -- Cross-org maintenance: key rotation, expiry sweeps, the bootstrap CLI.
    -- Exempt from RLS explicitly, rather than anyone disabling RLS globally.
    -- Must live here: CREATE ROLE requires superuser, and every migration after
    -- 0001 runs as signari_engine.
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'signari_maintenance') THEN
        CREATE ROLE signari_maintenance NOLOGIN BYPASSRLS;
    END IF;
END
$$;

-- ---------------------------------------------------------------------------
-- Schemas
-- ---------------------------------------------------------------------------
-- core     : protocol state. Owned by the engine. Migrated only by the engine.
-- core_v1  : read-only views over `core`, versioned. THE contract with the admin.
--            A view is a contract you hold stable while the physical table moves
--            underneath it -- the same mechanism pgroll uses for zero-downtime
--            migrations, doing double duty as the cross-runtime boundary.
-- admin    : Laravel's own tables (read models, jobs, cache, sessions, break-glass).
--            Migrated only by Laravel.

CREATE SCHEMA IF NOT EXISTS core     AUTHORIZATION signari_engine;
CREATE SCHEMA IF NOT EXISTS core_v1  AUTHORIZATION signari_engine;
CREATE SCHEMA IF NOT EXISTS admin    AUTHORIZATION signari_admin;

-- ---------------------------------------------------------------------------
-- The privilege boundary
-- ---------------------------------------------------------------------------
-- Nothing is implicitly granted. `public` must not be usable as a dumping ground.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- The admin can never touch core tables directly. This is the line that makes
-- "just this one direct read" impossible rather than merely discouraged.
REVOKE ALL ON SCHEMA core FROM signari_admin;
REVOKE ALL ON ALL TABLES IN SCHEMA core FROM signari_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE signari_engine IN SCHEMA core
    REVOKE ALL ON TABLES FROM signari_admin;

-- The admin may traverse core_v1 and SELECT from it. Nothing more.
GRANT USAGE ON SCHEMA core_v1 TO signari_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE signari_engine IN SCHEMA core_v1
    GRANT SELECT ON TABLES TO signari_admin;

-- The engine never touches the admin's schema. Symmetry matters: if the engine
-- can write admin tables, the admin's migrations become the engine's problem.
REVOKE ALL ON SCHEMA admin FROM signari_engine;
ALTER DEFAULT PRIVILEGES FOR ROLE signari_admin IN SCHEMA admin
    REVOKE ALL ON TABLES FROM signari_engine;

-- signari_maintenance is BYPASSRLS, but BYPASSRLS is not a grant -- it only exempts
-- the role from policies it would otherwise be subject to. Without these it can
-- see through RLS and still be denied at the schema. Set as DEFAULT PRIVILEGES
-- here, before 0002 creates the tables, so every future table is covered too.
GRANT USAGE ON SCHEMA core TO signari_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE signari_engine IN SCHEMA core
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO signari_maintenance;
ALTER DEFAULT PRIVILEGES FOR ROLE signari_engine IN SCHEMA core
    GRANT USAGE, SELECT ON SEQUENCES TO signari_maintenance;

-- ---------------------------------------------------------------------------
-- Migration ledger
-- ---------------------------------------------------------------------------
-- One ledger per schema. The engine gates startup on `core`'s ledger only, and
-- has no opinion about Laravel's. Two runtimes, two ledgers, no coordination.
--
-- `fingerprint` is a hash of the expected schema shape, not just a counter.
-- The engine refuses to start if the live schema does not match what the binary
-- was built against -- fail loudly at boot, not at 3am inside a query.

CREATE TABLE IF NOT EXISTS core.schema_migrations (
    version      integer      PRIMARY KEY,
    name         text         NOT NULL,
    fingerprint  text         NOT NULL,
    applied_at   timestamptz  NOT NULL DEFAULT now(),
    -- Version skips are refused. `signari upgrade --to N` walks 1..N internally and
    -- ships every intermediate migration set in the same image. Documentation
    -- telling users not to skip is not a mechanism; this is.
    CONSTRAINT schema_migrations_version_positive CHECK (version > 0)
);

-- 0001 runs as a superuser, so everything it CREATEs is owned by that superuser.
-- The ledger must be owned by signari_engine, because every migration from 0002
-- onward runs as signari_engine and writes to it. Getting this wrong fails at the
-- FIRST core migration with "permission denied for table schema_migrations" --
-- after the DDL has already been applied and rolled back, which is a confusing
-- place to land.
ALTER TABLE core.schema_migrations OWNER TO signari_engine;

-- Same reasoning for the schemas themselves: AUTHORIZATION on CREATE SCHEMA sets
-- the owner, but only when the schema did not already exist.
ALTER SCHEMA core    OWNER TO signari_engine;
ALTER SCHEMA core_v1 OWNER TO signari_engine;
ALTER SCHEMA admin   OWNER TO signari_admin;

COMMENT ON TABLE core.schema_migrations IS
    'Engine-owned migration ledger. Laravel has its own and the two never interact.';
