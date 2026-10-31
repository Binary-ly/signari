--
-- 0208_posix_ids.sql
--
-- A POSIX identity for every person and group (7.03), for hosts that read accounts
-- from the directory. The identifiers here are UUIDs and a host needs an integer, one
-- that owns files long after anybody remembers why.
--
-- From a sequence, because a number handed out twice gives a new employee an erased
-- one's files, and a sequence never goes back: deleting a person frees nothing. Users
-- and groups share it, so a person's number is free to serve as the gid of their own
-- group. It is deployment-wide rather than per organisation so that creating people
-- takes no lock, which lets a tenant who watches two of their own numbers estimate how
-- many accounts were made between them; nothing else of another tenant shows.
--
-- It starts at two thousand million. Numbers a company already has, kept from the
-- directory it is leaving, sit below that and can be set by hand, and no allocated
-- number can ever land on one. Hosts keep their own accounts low. The top is 2^31 - 2,
-- since a number past 2^31 is one some software still reads as negative.
--
-- NOT compatible with the previous release: filling a volatile default rewrites both
-- tables under an exclusive lock.

CREATE SEQUENCE core.posix_id_seq AS integer MINVALUE 2000000000 MAXVALUE 2147483646 START 2000000000;

ALTER TABLE core.users ADD COLUMN posix_uid integer NOT NULL DEFAULT nextval('core.posix_id_seq')
    CHECK (posix_uid >= 1000);
ALTER TABLE core.groups ADD COLUMN posix_gid integer NOT NULL DEFAULT nextval('core.posix_id_seq')
    CHECK (posix_gid >= 1000);

CREATE UNIQUE INDEX users_posix_uid ON core.users (org_id, posix_uid);
CREATE UNIQUE INDEX groups_posix_gid ON core.groups (org_id, posix_gid);
