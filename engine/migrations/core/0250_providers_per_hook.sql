-- 0250_providers_per_hook.sql
--
-- Several providers on a hook, each able to refuse (10.06). One provider per hook was the safe
-- answer to "which wins?", and a veto has no such question: everybody has to agree, so an
-- organisation's fraud check and its compliance check can both stand on a sign-in. Two hooks
-- keep one, because their answer is not a veto: a password has one verdict and a flow condition
-- one value. A claim stays disjoint by the writer, so no two providers can set the same thing.
-- Not compatible with the previous release, whose registration names the constraint dropped here.

ALTER TABLE core.providers DROP CONSTRAINT providers_org_id_hook_key;
ALTER TABLE core.providers ADD CONSTRAINT providers_org_hook_name_key UNIQUE (org_id, hook, name);
ALTER TABLE core.providers ADD COLUMN position integer NOT NULL DEFAULT 0;

CREATE UNIQUE INDEX providers_one_answer ON core.providers (org_id, hook)
    WHERE hook IN ('password_verify', 'flow_condition');
