SET search_path = core, public;

-- The access policy in force, for the console.
--
-- The document is the YAML file an operator wrote and applied, stored verbatim
-- as text rather than parsed into rows. That is the whole design: the policy is
-- version-controlled and reviewable in a pull request, so the thing to show is
-- the document, not a reconstruction of it.
--
-- "No policy" is a state worth showing rather than an empty screen: it means
-- every client is open to every user, which may well be correct and should be a
-- decision rather than a surprise.
CREATE VIEW core_v1.access_policies AS
SELECT
    p.org_id,
    p.document,
    p.applied_at,
    -- Cheap orientation without parsing YAML in SQL: how big it is, and whether
    -- it closes by default. A file whose last word is `deny` behaves very
    -- differently from one that does not, and it is the first thing to check.
    length(p.document)                                    AS document_bytes,
    array_length(string_to_array(p.document, E'\n'), 1)   AS line_count,
    -- Anchored at column 0 deliberately. `default` is a FILE-level key, and
    -- allowing leading whitespace would match a nested `default: deny` inside a
    -- rule -- reporting a closed policy for an open one, which is the wrong
    -- direction to be wrong on a security screen.
    --
    -- An absent key means "allow" (see internal/policy: allow is the default
    -- default), so false here is a real statement and not an unknown.
    (p.document ~ '(^|\n)default[ \t]*:[ \t]*deny')       AS denies_by_default
FROM core.access_policies p;

GRANT SELECT ON core_v1.access_policies TO signari_admin;
