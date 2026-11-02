-- signari:compatible-with-previous
-- 0264_group_members_view.sql
--
-- Who is in which group, for the console (0.28). A user manager delegated over some groups was
-- not offered the people screen at all, because it read everybody and nothing in core_v1 said who
-- was in what, so they administered their members through the Admin API alone. Group membership
-- is an organisation's own, and a view of it answers under the same policy as the rest.

CREATE VIEW core_v1.group_members AS
SELECT m.group_id, m.user_id, m.org_id
  FROM core.group_members m;

GRANT SELECT ON core_v1.group_members TO signari_admin;
