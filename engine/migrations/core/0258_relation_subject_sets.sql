-- signari:no-transaction
-- signari:compatible-with-previous
--
-- 0258_relation_subject_sets.sql
--
-- Relations held by a set of subjects (11.02). `team:eng#member` as a subject means everybody who
-- holds `member` on team:eng, and an evaluation has to find those on an object among however many
-- people hold the relation there themselves. Partial, because they are few and an object's own
-- viewers may be a great many, and only a request that has one pays anything for looking. An older
-- binary reads such a row as a subject nobody is.

CREATE INDEX CONCURRENTLY IF NOT EXISTS relations_subject_sets
    ON core.relations (org_id, object_type, object_id, relation) WHERE subject_id LIKE '%#%';
