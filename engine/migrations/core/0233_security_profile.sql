-- signari:compatible-with-previous
--
-- 0233_security_profile.sql
--
-- A client held to a security profile (9.05). FAPI 2.0 is a set of restrictions a deployment
-- turns on, not behaviour that is wrong by default, and most of what it restricts is already
-- a setting of the client: a client marked fapi2 is refused until its settings meet the
-- profile, and refused at the token endpoint if they stop meeting it. What is not a setting
-- follows from the mark: an assertion addressed only to the issuer, a refresh token that does
-- not rotate, a redirect_uri always pushed.

ALTER TABLE core.clients ADD COLUMN security_profile text NOT NULL DEFAULT 'none'
    CHECK (security_profile IN ('none', 'fapi2'));
