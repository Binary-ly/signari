-- signari:compatible-with-previous
--
-- 0170_webauthn_ceremony.sql
--
-- What an organisation asks of an authenticator (4.11): user verification at
-- a passkey sign-in, whether registration makes a discoverable credential,
-- which kind of authenticator, which algorithms, how long the browser waits,
-- and the hints it is given. Every one was fixed in code, so an organisation
-- issuing roaming security keys without PINs could not use them, and one
-- that wanted only platform authenticators could not say so.
--
-- The defaults are what the code did, so nothing changes until set. Compatible
-- with the release before, which ignores the columns and behaves as the
-- defaults.
ALTER TABLE core.webauthn_policy ADD COLUMN user_verification text NOT NULL DEFAULT 'required'
    CHECK (user_verification IN ('required', 'preferred'));
ALTER TABLE core.webauthn_policy ADD COLUMN resident_key text NOT NULL DEFAULT 'required'
    CHECK (resident_key IN ('required', 'preferred', 'discouraged'));
ALTER TABLE core.webauthn_policy ADD COLUMN attachment text NOT NULL DEFAULT ''
    CHECK (attachment IN ('', 'platform', 'cross-platform'));
ALTER TABLE core.webauthn_policy ADD COLUMN algorithms integer[] NOT NULL
    DEFAULT '{-7,-35,-36,-257,-258,-259,-37,-38,-39,-8}'
    CHECK (cardinality(algorithms) > 0 AND algorithms <@ '{-7,-35,-36,-257,-258,-259,-37,-38,-39,-8}');
ALTER TABLE core.webauthn_policy ADD COLUMN timeout_s integer NOT NULL DEFAULT 300
    CHECK (timeout_s BETWEEN 30 AND 300);
ALTER TABLE core.webauthn_policy ADD COLUMN hints text[] NOT NULL DEFAULT '{}'
    CHECK (hints <@ '{security-key,client-device,hybrid}');

COMMENT ON COLUMN core.webauthn_policy.user_verification IS
    'At a passkey sign-in: required (the default; the sign-in is multi-factor) or preferred '
    '(an authenticator without a PIN or biometric signs in, single-factor).';
COMMENT ON COLUMN core.webauthn_policy.resident_key IS
    'At registration: required (the default; usernameless sign-in), preferred or discouraged.';
COMMENT ON COLUMN core.webauthn_policy.attachment IS
    'At registration: empty for any, platform, or cross-platform.';
COMMENT ON COLUMN core.webauthn_policy.algorithms IS
    'COSE algorithms offered at registration, in preference order: -7 ES256, -35 ES384, '
    '-36 ES512, -257 RS256, -258 RS384, -259 RS512, -37 PS256, -38 PS384, -39 PS512, -8 EdDSA. '
    'The default is all ten, what registration offered before this column.';
COMMENT ON COLUMN core.webauthn_policy.timeout_s IS
    'Seconds the browser waits for the authenticator, and the server holds the challenge, '
    '30 to 300.';
COMMENT ON COLUMN core.webauthn_policy.hints IS
    'WebAuthn hints for the browser: security-key, client-device, hybrid.';
