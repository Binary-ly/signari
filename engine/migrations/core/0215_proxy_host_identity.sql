-- signari:compatible-with-previous
--
-- 0215_proxy_host_identity.sql
--
-- What a protected application is told about a person beyond who they are (8.24):
-- the groups released to it, and a signed statement it can check for itself. Each
-- is per host, because a group's name says something about a person, and an
-- application should hear only the ones it needs. Empty and off, it hears what it
-- always has.

ALTER TABLE core.proxy_hosts ADD COLUMN release_groups text[] NOT NULL DEFAULT '{}';
ALTER TABLE core.proxy_hosts ADD COLUMN signed_identity boolean NOT NULL DEFAULT false;
