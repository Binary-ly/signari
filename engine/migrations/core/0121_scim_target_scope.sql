-- Which people a provisioning target receives.
--
-- # The gap
--
-- Every active user in an organisation was provisioned to every target. So a
-- deployment with one SaaS application for engineering and another for finance
-- pushed everybody to both — paying for seats nobody uses and, more to the
-- point, creating accounts for people who should not have them. Provisioning is
-- access: an account at a target IS the ability to sign in there.
--
-- # NULL means everybody, which is what every target already does
--
-- Existing targets are unchanged. Scoping is opt-in for the same reason the
-- object restriction on admin tokens is: making it mandatory would break every
-- target already configured.
--
-- # Narrowing an existing target is a mass DEPROVISION, and the ceiling catches it
--
-- This is the dangerous edit. Pointing a target that provisions 400 people at a
-- group of 30 does not just stop provisioning the other 370 — the next
-- reconciliation sees 370 accounts that should not exist and deactivates them
-- at the remote system.
--
-- `provision.CheckSafety` already refuses a run that deactivates more than 25%
-- of managed accounts, which is exactly this shape, and it is deliberately not
-- configurable to zero. So the guard was already there; what is added here is
-- the thing that can trip it, and an operator who means it uses `-force` after
-- reading the plan.

ALTER TABLE core.scim_targets
    ADD COLUMN scope_group_id uuid REFERENCES core.groups(id) ON DELETE RESTRICT;

COMMENT ON COLUMN core.scim_targets.scope_group_id IS
    'Only members of this group are provisioned to this target. NULL provisions '
    'every active user in the organisation, which is what every target did '
    'before this column existed.';

-- ON DELETE RESTRICT, not CASCADE or SET NULL, and the choice matters.
--
-- CASCADE would delete the target because a group was deleted, silently ending
-- provisioning entirely. SET NULL would be worse: the target would widen from
-- thirty people to the whole organisation, creating accounts for everybody at a
-- remote system, as a side effect of deleting a group.
--
-- RESTRICT makes an operator deal with the target first, which is the only one
-- of the three where nobody is surprised.
