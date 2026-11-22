-- signari:compatible-with-previous
-- 0259_authorization_views.sql
--
-- What the console reads of authorization (11.14): who holds what on what, and the model that
-- says what it means. A person asking why somebody can see something had the command line. Only
-- the live relations, because a decision reads no others, so a row here is a row in force. The
-- compiled model stays behind: the source is what an operator wrote and what a review reads.

CREATE VIEW core_v1.relations AS
SELECT r.id, r.org_id, r.subject_type, r.subject_id, r.relation, r.object_type, r.object_id,
       r.granted_at, r.expires_at
  FROM core.relations r
 WHERE r.expires_at IS NULL OR r.expires_at > now();

CREATE VIEW core_v1.authorization_models AS
SELECT m.org_id, m.source, m.updated_at,
       array_length(string_to_array(m.source, E'\n'), 1) AS line_count
  FROM core.authorization_models m;

GRANT SELECT ON core_v1.relations, core_v1.authorization_models TO signari_admin;
