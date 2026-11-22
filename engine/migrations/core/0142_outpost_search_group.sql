-- 0142_outpost_search_group.sql
--
-- The core, not the outpost, decides who behind an LDAP outpost may read the
-- directory.
--
-- # The defect
--
-- An LDAP outpost answers a subtree search for members of its search group and
-- only their own entry for everyone else. It enforced that itself, from an
-- environment variable on the outpost's host, and then asked the core for the
-- directory with nothing but its token. So the token alone, used directly
-- against the core, listed every account in the organisation, whatever group
-- the outpost had been given.
--
-- # Now
--
-- The search group is recorded on the outpost's registration. NULL means no
-- one behind this outpost may read anyone's entry but their own. The core
-- answers a directory request only with proof that somebody bound through this
-- outpost (see internal/httpapi/outpost.go), and with the whole directory only
-- when that person is, as they stand now, a member of this group.

SET search_path = core, public;

ALTER TABLE outposts ADD COLUMN search_group text;
