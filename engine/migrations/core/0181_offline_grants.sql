-- 0181_offline_grants.sql
--
-- A grant of offline_access outlives the session it was given in.
--
-- # The defect
--
-- A refresh token is issued only when offline_access is granted, and its
-- family was revoked when the session ended and refused once the session
-- expired. So "offline" access lasted as long as the person stayed signed in
-- -- twelve hours at most -- whatever refresh lifetime the client was given.
-- An application that asked for access while its user was away had it only
-- while they were not.
--
-- # How
--
-- offline_lifetime_s is how long an organisation lets such a grant last from
-- the moment it is given, thirty days unless changed; 0 keeps the old rule,
-- that the grant ends with the session. A family started under it carries
-- offline_not_after, fixed when it starts and never moved: that is the
-- absolute bound a lineage rotates within, as the session's own deadline is
-- for one that is not offline. A family started in an impersonation is never
-- offline: support access must end when the episode does.
--
-- Ending a session no longer ends the offline grants made in it, unless it
-- ends for a reason that means the account may be in other hands (store
-- TerminationReason.EndsOfflineGrants). Withdrawing consent ends them, as
-- before. The session row is kept while an offline grant made in it is live,
-- because a refresh checks the client's floor against how that session signed
-- in.
--
-- Not compatible with the release before: its rotation would refuse every
-- offline grant whose session has ended, which this one keeps.

ALTER TABLE core.organizations
    ADD COLUMN offline_lifetime_s integer NOT NULL DEFAULT 2592000
        CHECK (offline_lifetime_s = 0 OR offline_lifetime_s BETWEEN 3600 AND 31536000);

COMMENT ON COLUMN core.organizations.offline_lifetime_s IS
    'How long a grant of offline_access lasts from when it is given, in seconds; 0 ends it with the session. `signari instance session-lifetime -offline`.';

ALTER TABLE core.refresh_token_families ADD COLUMN offline_not_after timestamptz;

COMMENT ON COLUMN core.refresh_token_families.offline_not_after IS
    'When an offline grant ends whatever its session does; NULL for a family that ends with its session.';
