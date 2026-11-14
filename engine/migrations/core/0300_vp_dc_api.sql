-- 0300_vp_dc_api.sql
--
-- A wallet sign-in may ask through the browser's Digital Credentials API, when its operator
-- turns that on (vp_verifiers.dc_api, off by default): the request goes to the browser in the
-- page, and the wallet's answer comes back to that page, bound to its origin
-- (specs/oid4vp.txt:2423-2689). Such a request is marked on its pending sign-in, so it is never
-- answered at the response URI or by a response code. Compatible with the previous release,
-- which reads none of it and offers the other ways alone.
-- signari:compatible-with-previous

ALTER TABLE core.vp_verifiers ADD COLUMN dc_api boolean NOT NULL DEFAULT false;

ALTER TABLE core.federated_logins ADD COLUMN vp_dc_api boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.vp_verifiers.dc_api IS
    'the sign-in page asks through the browser''s Digital Credentials API too';

COMMENT ON COLUMN core.federated_logins.vp_dc_api IS
    'a request handed to the browser''s Digital Credentials API, answered only through the page that asked';
