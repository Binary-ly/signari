-- signari:compatible-with-previous
--
-- 0172_sms_delegated_codes.sql
--
-- A text-message code a delegated verification service made, sent and will
-- check (4.13, SIGNARI_SMS_GATEWAY=verify-webhook). This engine never holds
-- it: the outstanding code's code_hash is random bytes, the hash of no code,
-- so the purpose-and-hash constraint keeps holding, and code_delegated says
-- the service is to be asked instead.
--
-- Compatible with the release before, which ignores the column and compares a
-- typed code against those random bytes: a delegated code is refused there,
-- not accepted.
ALTER TABLE core.sms_otp_credentials ADD COLUMN code_delegated boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.sms_otp_credentials.code_delegated IS
    'The outstanding code was made, sent and will be checked by the delegated verification '
    'service; code_hash then holds random bytes that match no code.';
