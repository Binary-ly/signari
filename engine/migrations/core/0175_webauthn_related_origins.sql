-- signari:compatible-with-previous
--
-- 0175_webauthn_related_origins.sql
--
-- Other origins a passkey made under this instance's RP ID may be used from
-- (4.23; WebAuthn Level 3 §5.11, related origin requests): a country domain, a
-- brand domain, an application on another host. The browser checks the list at
-- https://<rp_id>/.well-known/webauthn, which the engine serves when the RP ID
-- is its own host, and the engine accepts a ceremony from each origin listed.
--
-- Compatible with the release before, which ignores the column and refuses a
-- ceremony from any of them, as it did.
ALTER TABLE core.instances ADD COLUMN webauthn_related_origins text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN core.instances.webauthn_related_origins IS
    'Web origins (https://host[:port]) a passkey under rp_id may also be used from, served at '
    '/.well-known/webauthn. Set with `signari instance related-origins`.';
