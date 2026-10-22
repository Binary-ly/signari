-- 0186_signup_approval.sql
--
-- An organisation may hold its self-sign-ups for an administrator's approval
-- (5.19).
--
-- A sign-up rule let anybody at an allowed domain in at once; an organisation
-- that wanted somebody to look first had only "no self-sign-up at all". With
-- require_approval on, an account self-sign-up makes is `pending`: it exists
-- and holds its password, and signs nobody in, because every sign-in reads
-- `status = 'active'`, until an administrator activates it. Accounts made by
-- invitation or by an administrator are never pending: somebody already chose
-- them.
--
-- Not declared compatible: the release before would read a pending account as
-- one it may not sign in, which is right, but the check is a constraint on a
-- table it has, which the declaration refuses.

ALTER TABLE core.users DROP CONSTRAINT users_status_check;
ALTER TABLE core.users ADD CONSTRAINT users_status_check
    CHECK (status IN ('active', 'deactivated', 'locked', 'pending'));

ALTER TABLE core.signup_rules ADD COLUMN require_approval boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.signup_rules.require_approval IS
    'Whether an account this rule lets sign up waits, pending, for an administrator to activate it. `signari signup enable -require-approval`.';
