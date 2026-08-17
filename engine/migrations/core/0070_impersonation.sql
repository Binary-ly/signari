-- Support access: an administrator acting as a user, visibly.
--
-- # Why the relying party is told
--
-- The usual implementation of this feature issues a session indistinguishable
-- from the user's own. The identity provider logs who did it; every downstream
-- application sees the user and nothing else. So the audit trail that matters --
-- the one in the application where the damage would be done -- records the user
-- as having done it themselves, and they have no way to prove otherwise.
--
-- RFC 8693 already has the claim for this: `act`, the actor. A session started
-- this way carries the administrator's identity in every token minted from it,
-- so an application can refuse the request, label the record, or write its own
-- log entry naming the real actor. Nothing downstream has to trust our log.
--
-- # Why it ends by itself
--
-- Support access nobody remembered to close is a live administrative session
-- wearing somebody else's name. It expires whether or not anyone stops it.

CREATE TABLE core.impersonations (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id        uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The administrator, and the person they are acting as. Never the same:
    -- "impersonating yourself" is a way to launder an action into an
    -- unattributable one.
    actor_id      uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    subject_id    uuid        NOT NULL REFERENCES core.users(id) ON DELETE CASCADE,
    CONSTRAINT impersonation_is_of_somebody_else CHECK (actor_id <> subject_id),

    -- Required, and stored. An organisation that cannot answer "why was this
    -- account accessed" does not have support access, it has a back door.
    reason        text        NOT NULL,
    CONSTRAINT impersonation_reason_is_meaningful CHECK (length(btrim(reason)) >= 8),

    -- The session created for it, so stopping is a single lookup and so the
    -- audit row and the live session cannot disagree about which is which.
    sid           text        REFERENCES core.sessions(sid) ON DELETE SET NULL,

    started_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    ended_at      timestamptz,
    ended_reason  text,

    correlation_id text
);

CREATE INDEX impersonations_live ON core.impersonations (org_id, expires_at)
    WHERE ended_at IS NULL;
CREATE INDEX impersonations_by_subject ON core.impersonations (subject_id, started_at DESC);

ALTER TABLE core.impersonations ENABLE ROW LEVEL SECURITY;

-- The engine hatch. Without core.is_engine() the engine reads zero rows, and
-- because a development DSN is usually a superuser -- which bypasses RLS
-- entirely -- that failure is invisible until it is deployed. See 0058.
CREATE POLICY impersonations_org ON core.impersonations
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT, INSERT, UPDATE ON core.impersonations TO signari_engine;

-- The session carries the actor, so token minting needs no second lookup and
-- cannot forget one. ON DELETE SET NULL rather than CASCADE: deleting an
-- administrator must not silently delete the record of what they did.
ALTER TABLE core.sessions
    ADD COLUMN impersonator_id uuid REFERENCES core.users(id) ON DELETE SET NULL;

COMMENT ON COLUMN core.sessions.impersonator_id IS
    'Set when this session was started by an administrator acting as the user. '
    'Emitted as the RFC 8693 `act` claim in every token minted from it.';

-- The revocation_reason CHECK enumerates the reasons, so a new one must be added
-- HERE or every stop fails at runtime with a constraint violation -- which the
-- Go constant compiles perfectly happily into.
ALTER TABLE core.sessions DROP CONSTRAINT sessions_revocation_reason_check;
ALTER TABLE core.sessions ADD CONSTRAINT sessions_revocation_reason_check
    CHECK (revocation_reason IN
        ('logout','admin_revoke','user_deleted','user_deactivated',
         'password_change','mfa_reset','expired','reuse_detected',
         'impersonation_ended'));

-- Who may do this.
--
-- A capability on a group rather than a role system, because a role system is a
-- larger thing than this feature needs and inventing one here would give
-- "administrator" a meaning that quietly grows. This grants exactly one power
-- and names it.
--
-- Nobody has it by default. A feature like this arriving switched on for whoever
-- happens to be in a group called "admins" is a privilege escalation delivered
-- by an upgrade.
ALTER TABLE core.groups
    ADD COLUMN may_impersonate boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.groups.may_impersonate IS
    'Members may start support access as another user in the same organisation.';
