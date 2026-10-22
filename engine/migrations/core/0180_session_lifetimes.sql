-- 0180_session_lifetimes.sql
--
-- How long a session lasts, per organisation, and how long it lasts unused.
--
-- # The defect
--
-- Every session lasted twelve hours from sign-in, a constant in the engine,
-- whatever the organisation needed, and one left untouched for eleven of them
-- was as good as one used a minute ago. An organisation that wanted a shorter
-- day, or a session that ends when its holder walks away, could not have either.
--
-- # How
--
-- session_lifetime_s is the absolute lifetime, twelve hours unless changed.
-- session_idle_s, when set, ends a session that long after it was last used.
--
-- Each session keeps two deadlines. absolute_not_after is fixed at sign-in and
-- never moves later. not_after is the one every check already reads; it starts
-- at the sooner of the two and, on use, moves to the sooner of the absolute
-- deadline and now plus the idle limit. The CHECK holds not_after inside
-- absolute_not_after, so no statement, present or future, can extend a session
-- past the lifetime it was signed in with: that is the bound a refresh token's
-- lineage takes its absolute expiry from. Moving it is written at most once a
-- minute (last_seen_at), so a busy session costs one write a minute rather than
-- one a request, which is why the idle limit is at least five minutes.
--
-- The BEFORE INSERT trigger gives a row inserted with only not_after the same
-- deadline as its absolute one, so a writer that knows nothing of idleness
-- still makes a valid session.
--
-- Not compatible with the release before: a constraint and a trigger on a
-- table it has.

ALTER TABLE core.organizations
    ADD COLUMN session_lifetime_s integer NOT NULL DEFAULT 43200
        CHECK (session_lifetime_s BETWEEN 300 AND 2592000);
ALTER TABLE core.organizations ADD COLUMN session_idle_s integer;
ALTER TABLE core.organizations ADD CONSTRAINT organizations_session_idle_bounds
    CHECK (session_idle_s IS NULL OR (session_idle_s >= 300 AND session_idle_s <= session_lifetime_s));

COMMENT ON COLUMN core.organizations.session_lifetime_s IS
    'How long a session lasts from sign-in, in seconds. `signari instance session-lifetime`.';
COMMENT ON COLUMN core.organizations.session_idle_s IS
    'How long a session lasts unused, in seconds; NULL is no limit. `signari instance session-lifetime`.';

ALTER TABLE core.sessions ADD COLUMN absolute_not_after timestamptz;
ALTER TABLE core.sessions ADD COLUMN last_seen_at timestamptz;
UPDATE core.sessions SET absolute_not_after = not_after, last_seen_at = auth_time;
ALTER TABLE core.sessions ALTER COLUMN absolute_not_after SET NOT NULL;
ALTER TABLE core.sessions ALTER COLUMN last_seen_at SET NOT NULL;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_not_after_within_lifetime
    CHECK (not_after <= absolute_not_after);

CREATE FUNCTION core.session_deadlines_default() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    NEW.absolute_not_after := coalesce(NEW.absolute_not_after, NEW.not_after);
    NEW.last_seen_at := coalesce(NEW.last_seen_at, NEW.auth_time, now());
    RETURN NEW;
END $$;

CREATE TRIGGER sessions_deadlines_default BEFORE INSERT ON core.sessions
    FOR EACH ROW EXECUTE FUNCTION core.session_deadlines_default();
