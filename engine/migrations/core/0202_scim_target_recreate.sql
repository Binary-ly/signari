-- signari:compatible-with-previous
--
-- 0202_scim_target_recreate.sql
--
-- Whether a sync gives somebody back an account deleted at the target (7.14). A
-- link said they had one, so nothing ever looked, and a person removed there by
-- hand stayed removed for as long as they stayed active here.
--
-- Off by default. Deleting somebody at the target may have been a decision, and
-- finding out means listing the target on every sync.

ALTER TABLE core.scim_targets
    ADD COLUMN recreate_missing boolean NOT NULL DEFAULT false;
