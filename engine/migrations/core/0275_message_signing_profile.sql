-- 0275_message_signing_profile.sql
--
-- FAPI 2.0 Message Signing as a security profile, the Security Profile and signed
-- requests and responses besides. Not compatible with the previous release in the one
-- way that matters: a client set to it is not a profile that release knows.

ALTER TABLE core.clients DROP CONSTRAINT clients_security_profile_check;
ALTER TABLE core.clients ADD CONSTRAINT clients_security_profile_check
    CHECK (security_profile IN ('none', 'fapi2', 'fapi2-message-signing'));
