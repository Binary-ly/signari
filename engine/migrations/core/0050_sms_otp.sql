-- SMS as a second factor.
--
-- Modelled on core.email_otp_credentials, column for column where the meaning
-- is the same. One live code, a resend interval, a bounded attempt count: the
-- same three rules, because two sets of rules for two channels means one of
-- them is missing a check, and it is always the second one.
--
-- # This is the weakest factor offered here
--
-- SIM swap needs no technical exploit at all -- somebody persuades a mobile
-- operator to move a number. SS7 access is purchasable. Several operators will
-- forward texts to an email address configured through a web portal.
--
-- It is offered because the alternative most people choose is not a passkey, it
-- is nothing, and SMS still defeats credential stuffing. What it must never do
-- is silently satisfy a policy that asked for a phishing-resistant factor;
-- that is why the amr value is 'sms' and not something vaguer.
CREATE TABLE IF NOT EXISTS core.sms_otp_credentials (
    user_id         uuid PRIMARY KEY REFERENCES core.users(id) ON DELETE CASCADE,
    org_id          uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- E.164, with the leading +. One spelling only: two spellings of one number
    -- that both work means enrolling +447700900123 and being challenged on
    -- 07700900123, or a lookup that misses and silently creates a second
    -- credential for the same phone.
    number          text NOT NULL,

    -- The live code, hashed. Never the code itself: a database read would
    -- otherwise hand over a second factor for every account mid-sign-in.
    code_hash       bytea,
    code_expires_at timestamptz,
    attempts        integer NOT NULL DEFAULT 0,
    last_sent_at    timestamptz,

    -- Enrolment is not complete until a code sent to the number is returned.
    -- Without this, a typo enrols a factor on somebody else's phone and the
    -- owner of the account is locked out by their own security setting.
    verified_at     timestamptz,

    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT sms_otp_number_e164 CHECK (number ~ '^\+[1-9][0-9]{6,14}$')
);

COMMENT ON CONSTRAINT sms_otp_number_e164 ON core.sms_otp_credentials IS
    'E.164 enforced in the database as well as in code: the application is not '
    'the only thing that writes here, and a number in the wrong format sends '
    'somebody a code they did not ask for.';

ALTER TABLE core.sms_otp_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.sms_otp_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sms_otp_org_isolation ON core.sms_otp_credentials;
CREATE POLICY sms_otp_org_isolation ON core.sms_otp_credentials
    USING (core.is_engine() OR org_id = core.current_org_id());
