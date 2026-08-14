-- 0031_frontchannel_logout.sql
--
-- OpenID Connect Front-Channel Logout 1.0.
--
-- # Why BOTH channels, when back-channel already works
--
-- Back-channel logout is server-to-server: reliable, retryable, and invisible to
-- the browser. It is the right primary mechanism and this engine has had it from
-- the start.
--
-- What it cannot do is clear state the BROWSER holds. A relying party that keeps
-- its session in a cookie the server never sees -- or in local storage, or in a
-- service worker -- is still signed in from the user's point of view after a
-- perfect back-channel logout. The front channel exists to reach that state, by
-- loading a URL in the browser that the relying party can act on.
--
-- Neither is sufficient alone, and the honest position is to run both and report
-- what each achieved.

SET search_path = core, public;

ALTER TABLE clients
    ADD COLUMN frontchannel_logout_uri text,
    -- Whether the URI must carry `iss` and `sid`. Required by the specification
    -- when the RP asks for it, and it matters: without `sid` a relying party
    -- with several sessions for one person cannot tell which to end, so it ends
    -- all of them or none.
    ADD COLUMN frontchannel_logout_session_required boolean NOT NULL DEFAULT true;

-- https only, and no fragment. This URL is loaded in a frame during logout;
-- plaintext would announce the session id over the network in the clear.
ALTER TABLE clients ADD CONSTRAINT clients_frontchannel_https CHECK (
    frontchannel_logout_uri IS NULL
    OR (frontchannel_logout_uri LIKE 'https://%' AND position('#' in frontchannel_logout_uri) = 0)
);
