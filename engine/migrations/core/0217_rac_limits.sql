-- signari:compatible-with-previous
--
-- 0217_rac_limits.sql
--
-- How many may hold a remote connection at once, and for how long (8.29). A jump host
-- with a licence for two seats and a session left open over a weekend are the same
-- problem: nothing here could say no.
--
-- max_connections and max_duration_seconds are 0 for no limit. last_seen_at is written
-- each time an open channel is asked again, because a count of sessions that have not
-- ended would otherwise include every one a crashed process never got to end, and a
-- full connection would stay full for good.

ALTER TABLE core.rac_connections ADD COLUMN max_connections integer NOT NULL DEFAULT 0;
ALTER TABLE core.rac_connections ADD COLUMN max_duration_seconds integer NOT NULL DEFAULT 0;
ALTER TABLE core.rac_sessions ADD COLUMN last_seen_at timestamptz;
