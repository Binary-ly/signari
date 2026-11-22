-- signari:compatible-with-previous
--
-- 0294_codes_bound_to_the_attempt.sql
--
-- An emailed or texted sign-in code is bound to the sign-in that asked for it (ASVS 5.0.0
-- V6.6.2): the hash of the attempt its pending token names is kept beside the code, and the
-- code is refused to any other attempt, earlier or later. Until now a code was bound only to
-- the person, so one sent for a sign-in in one browser could finish another, and an LDAP bind
-- or a desktop sign-in, neither of which sends a code, took one sent for something else.
-- Compatible with the previous release, which neither writes nor reads the column and so goes
-- on binding a code to the person; a code it sent is refused here, and the person asks again.

ALTER TABLE core.email_otp_credentials
    ADD COLUMN code_attempt bytea CHECK (code_attempt IS NULL OR length(code_attempt) = 32);

ALTER TABLE core.sms_otp_credentials
    ADD COLUMN code_attempt bytea CHECK (code_attempt IS NULL OR length(code_attempt) = 32);
