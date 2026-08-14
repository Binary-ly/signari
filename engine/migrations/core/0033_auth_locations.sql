-- 0033_auth_locations.sql
--
-- Where authentications came from, for impossible-travel detection.
--
-- # What is stored, and what deliberately is not
--
-- NOT the IP address. This schema has hashed addresses from the beginning
-- (`sessions.ip_hash`) precisely so a breach does not hand somebody a movement
-- log for every user.
--
-- What impossible travel actually needs is a coarse position and a time. So that
-- is what is kept: country, region, and a location rounded to roughly city
-- precision. It answers "could this person have travelled between these two
-- points" without storing where they live.
--
-- The rounding is not cosmetic. Two decimal places is about a kilometre --
-- enough to compute a plausible speed over hundreds of kilometres, useless for
-- locating somebody's home.

SET search_path = core, public;

CREATE TABLE auth_locations (
    id          bigserial   PRIMARY KEY,
    user_id     uuid        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_id      uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    occurred_at timestamptz NOT NULL DEFAULT now(),

    country     text,
    region      text,
    -- Rounded to two decimal places by the writer. numeric, not float: the
    -- comparison is arithmetic and a float's last digits would differ between
    -- platforms for no benefit.
    latitude    numeric(5,2),
    longitude   numeric(6,2),

    -- Where the position came from, so a deployment can tell "no database
    -- configured" from "the address was not in it". Both mean no check happened,
    -- and only one is an operator's to fix.
    source      text        NOT NULL DEFAULT 'geoip'
                            CHECK (source IN ('geoip','header','unknown'))
);

-- The only query this table serves: the previous location for one user.
CREATE INDEX auth_locations_user_time_idx ON auth_locations (user_id, occurred_at DESC);

ALTER TABLE auth_locations ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_locations FORCE ROW LEVEL SECURITY;
CREATE POLICY auth_locations_org_isolation ON auth_locations
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON auth_locations TO signari_maintenance;
