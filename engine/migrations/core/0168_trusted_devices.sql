-- signari:compatible-with-previous
--
-- 0168_trusted_devices.sql
--
-- A device a person chose to remember after a second factor (4.05), so the
-- organisation's sign-in flow does not ask for one there again for a while.
--
-- A row, not a signed cookie alone: the browser holds a random token and this
-- holds its hash, so a remembered device is checked against the database on
-- every sign-in (ADR-007) and forgetting it -- by the person, by signing out
-- everywhere, by the organisation turning the feature off -- takes effect at
-- the next sign-in. A signed cookie could only be waited out.
--
-- Off by default: remember_device_days 0 offers nothing. Compatible with the
-- release before, which never reads either.

ALTER TABLE core.organizations ADD COLUMN remember_device_days integer NOT NULL DEFAULT 0
    CHECK (remember_device_days BETWEEN 0 AND 90);

COMMENT ON COLUMN core.organizations.remember_device_days IS
    'Days a device a person chose to remember after a second factor is not asked for one '
    'again by the sign-in flow. 0, the default, offers no such choice; at most 90. Set with '
    '`signari instance remember-device`.';

CREATE TABLE core.trusted_devices (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    user_id      uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    -- SHA-256 of the cookie's token. The token itself is never stored.
    token_hash   bytea       NOT NULL UNIQUE,
    -- What the person sees when deciding which to forget.
    user_agent   text        NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE INDEX trusted_devices_user ON core.trusted_devices (user_id);
CREATE INDEX trusted_devices_org ON core.trusted_devices (org_id);

ALTER TABLE core.trusted_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.trusted_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY trusted_devices_org_isolation ON core.trusted_devices
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.trusted_devices TO signari_maintenance;

-- Every core table carries 0139's trigger, so a CLI write moves the version.
CREATE TRIGGER trusted_devices_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.trusted_devices
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

COMMENT ON TABLE core.trusted_devices IS
    'Devices people chose to remember after a second factor. Checked on every sign-in; '
    'revoked_at, expiry, or the organisation''s remember_device_days at 0 end one.';
