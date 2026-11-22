-- 0290_yubico_otp.sql
--
-- A YubiKey's own one-time passwords as a person's second factor (4.27): the characters it
-- types when touched, checked against the token's AES key with no validation service asked.
-- A token is a credential of kind 'yubico' and algorithm 'AES128', its public ID kept beside
-- it. Not compatible with the previous release, which reads a credential of a kind it does
-- not know as a time-based one and would check six-digit codes against the token's key.

ALTER TABLE core.totp_credentials DROP CONSTRAINT totp_credentials_kind_check;
ALTER TABLE core.totp_credentials ADD CONSTRAINT totp_credentials_kind_check
    CHECK (kind IN ('totp', 'hotp', 'yubico'));
ALTER TABLE core.totp_credentials DROP CONSTRAINT totp_credentials_algorithm_check;
ALTER TABLE core.totp_credentials ADD CONSTRAINT totp_credentials_algorithm_check
    CHECK (algorithm IN ('SHA1', 'SHA256', 'SHA512', 'AES128'));

-- The public ID is what the token types first, unchanged, before the encrypted part: one to
-- sixteen bytes in modhex. A Yubico token has one and nothing else has any; AES128 is a
-- Yubico token's and nothing else's.
ALTER TABLE core.totp_credentials ADD COLUMN yubico_public_id text
    CHECK (yubico_public_id ~ '^([cbdefghijklnrtuv]{2}){1,16}$');
ALTER TABLE core.totp_credentials ADD CONSTRAINT totp_credentials_yubico_shape
    CHECK ((kind = 'yubico') = (yubico_public_id IS NOT NULL)
       AND (kind = 'yubico') = (algorithm = 'AES128'));

-- One holder per token, across every organisation. The counter that keeps an OTP from being
-- accepted twice is kept per credential, so a token held twice has two counters, and an OTP
-- spent at one account is still unspent at the other.
CREATE UNIQUE INDEX totp_credentials_yubico_public_id
    ON core.totp_credentials (yubico_public_id) WHERE yubico_public_id IS NOT NULL;

COMMENT ON COLUMN core.totp_credentials.kind IS
    'totp (time-based: an app or a hardware TOTP token), hotp (counter-based: a hardware token; '
    'last_used_counter is its last accepted press) or yubico (a YubiKey''s Yubico OTP: '
    'secret_enc seals its AES key and private ID, and last_used_counter is the use and session '
    'counters of its last accepted OTP as use*256 + session). Tokens are assigned with '
    '`signari user assign-otp`.';
COMMENT ON COLUMN core.totp_credentials.algorithm IS
    'What the authenticator computes codes with: HMAC with SHA1, SHA256 or SHA512, or AES128 for a '
    'Yubico OTP token.';
COMMENT ON COLUMN core.totp_credentials.yubico_public_id IS
    'A Yubico OTP token''s public ID, in modhex: the characters it types before the encrypted '
    'part. An OTP is checked only when it begins with them. Unique: a token has one holder.';
