-- signari:compatible-with-previous
-- 0247_proxy_host_cookie.sql
--
-- Where the proxy cookie of a protected application lives (8.25). One domain for the whole
-- deployment meant every application had to sit under one parent with the issuer, and one on
-- another domain could not be protected at all: a cookie can only be set for a domain the host
-- setting it is under. cookie_domain gives a host a parent of its own. own_cookie gives it a
-- cookie of its own, set on its own address through a path its proxy routes back here. An older
-- binary ignores both, and refuses such a host at sign-in by the check it has always made.

ALTER TABLE core.proxy_hosts ADD COLUMN cookie_domain text NOT NULL DEFAULT '';
ALTER TABLE core.proxy_hosts ADD COLUMN own_cookie boolean NOT NULL DEFAULT false;
