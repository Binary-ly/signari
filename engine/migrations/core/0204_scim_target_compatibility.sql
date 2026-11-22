-- signari:compatible-with-previous
--
-- 0204_scim_target_compatibility.sql
--
-- What a provisioning target needs that the protocol does not say it should
-- (7.11): one that refuses PATCH, one that refuses a filter, one that refuses a
-- member with no type. By what they do rather than which product: a target can
-- need several, and which needs which changes with its version.

ALTER TABLE core.scim_targets
    ADD COLUMN compatibility text[] NOT NULL DEFAULT '{}'
        CHECK (compatibility <@ ARRAY['no-patch', 'no-filter', 'typed-members']);
