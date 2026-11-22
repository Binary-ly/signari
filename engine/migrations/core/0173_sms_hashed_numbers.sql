-- 0173_sms_hashed_numbers.sql
--
-- An organisation may keep only a keyed hash of each person's phone number
-- (4.28). The number was stored in the clear, so a read of this table gave
-- every person's number, which is what a SIM swap starts from.
--
-- Hashed, the person retypes the number to be sent a sign-in code, and the
-- engine compares its hash. The key is derived from the person's own subject
-- key, sealed under the root key, so a copy of the database cannot test
-- guesses, a root-key rotation leaves it unchanged, the same number in two
-- accounts hashes differently, and erasure destroys it. Account notices are
-- not texted to a number the engine does not have.
--
-- code_ref is a delegated verification service's id for the outstanding code,
-- which is how its check is made without the number.
--
-- Not compatible with the release before: it reads number as never null.
ALTER TABLE core.sms_otp_credentials ALTER COLUMN number DROP NOT NULL;
ALTER TABLE core.sms_otp_credentials ADD COLUMN number_hash bytea;
ALTER TABLE core.sms_otp_credentials ADD COLUMN pending_hash bytea;
ALTER TABLE core.sms_otp_credentials ADD COLUMN code_ref text;
ALTER TABLE core.sms_otp_credentials ADD CONSTRAINT sms_otp_has_a_number
    CHECK (number IS NOT NULL OR number_hash IS NOT NULL OR pending_hash IS NOT NULL);

ALTER TABLE core.organizations ADD COLUMN sms_numbers text NOT NULL DEFAULT 'stored'
    CHECK (sms_numbers IN ('stored', 'hashed'));

COMMENT ON COLUMN core.sms_otp_credentials.number_hash IS
    'In an organisation that keeps hashes (organizations.sms_numbers), the proved number''s '
    'keyed hash under the person''s subject key; number is then NULL.';
COMMENT ON COLUMN core.sms_otp_credentials.pending_hash IS
    'The keyed hash of a number being enrolled in such an organisation; pending_number is NULL.';
COMMENT ON COLUMN core.sms_otp_credentials.code_ref IS
    'The delegated verification service''s id for the outstanding code, sent with its check.';
COMMENT ON COLUMN core.organizations.sms_numbers IS
    'stored (the default) or hashed: whether SMS numbers are kept, or only a keyed hash the '
    'person''s retyped number is compared with. Set with `signari instance sms-numbers`.';
