
SET search_path = core, public;

-- Which flow created the row. Existing rows are device authorizations, which is
-- what the default records -- there is no CIBA request predating this migration.
ALTER TABLE core.device_authorizations
    ADD COLUMN flow text NOT NULL DEFAULT 'device'
        CHECK (flow IN ('device', 'ciba'));

-- CIBA has no user code by default.
--
-- RFC 8628 needs one because the person is at a device that cannot show a URL
-- they can type; CIBA reaches them out of band, so there is nothing to read off
-- a screen. §7.1 makes `user_code` OPTIONAL and gates it on the OP advertising
-- backchannel_user_code_parameter_supported, which we do not.
--
-- The UNIQUE index is unaffected: Postgres treats NULLs as distinct, so any
-- number of CIBA rows can carry no user code without colliding.
ALTER TABLE core.device_authorizations
    ALTER COLUMN user_code_hash DROP NOT NULL;

-- A device authorization must still have one. Dropping NOT NULL above would
-- otherwise have quietly weakened the older flow to make room for the newer,
-- which is how a migration for one feature becomes a defect in another.
ALTER TABLE core.device_authorizations
    ADD CONSTRAINT device_flow_has_user_code
        CHECK (flow <> 'device' OR user_code_hash IS NOT NULL);

-- §7.1: "OPTIONAL. A human readable identifier or message intended to be
-- displayed on both the consumption device and the authentication device".
--
-- It is what lets somebody approving on their phone tell that the prompt belongs
-- to the transaction in front of them rather than to an attacker's request that
-- arrived at the same moment. Stored so the approval screen can show it.
ALTER TABLE core.device_authorizations
    ADD COLUMN binding_message text;

-- §7.1: the requested acr_values, carried so the approval can be held to them.
ALTER TABLE core.device_authorizations
    ADD COLUMN requested_acr text[] NOT NULL DEFAULT '{}';

-- A CIBA request names its subject UP FRONT, from the hint, while still pending.
--
-- This is the structural difference from the device flow, where the person is
-- discovered when they type the user code. Here the client says who it wants,
-- the server resolves them, and only that person can approve.
--
-- The existing constraint (approved implies user_id) still holds. This one adds
-- the other half for CIBA: a pending CIBA request must ALREADY know its subject,
-- because a request nobody is identified for is a prompt that cannot be
-- delivered to anybody.
ALTER TABLE core.device_authorizations
    ADD CONSTRAINT ciba_names_its_subject
        CHECK (flow <> 'ciba' OR user_id IS NOT NULL);

-- Finding a person's pending backchannel requests is the approval screen's only
-- query, and it runs on a path somebody is waiting on.
CREATE INDEX device_authorizations_ciba_pending
    ON core.device_authorizations (user_id, status)
    WHERE flow = 'ciba';

COMMENT ON COLUMN core.device_authorizations.flow IS
    'Which specification created this row: RFC 8628 device authorization, or CIBA Core 1.0 backchannel authentication. Both share the polling discipline, which the two documents specify identically.';
COMMENT ON COLUMN core.device_authorizations.binding_message IS
    'CIBA Core 1.0 section 7.1: shown on both the consumption and authentication devices so the person approving can tell which transaction they are approving.';
