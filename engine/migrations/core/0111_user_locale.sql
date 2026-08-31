-- A per-user language, for messages the account holder reads.
--
-- # Why this cannot come from the request
--
-- Every account-security notice this engine sends -- "your password was
-- changed", "a passkey was added", "a password reset was requested" -- exists to
-- reach the ACCOUNT HOLDER on a channel whoever triggered the action may not
-- control. NIST SP 800-63B-4 asks for the notification for exactly that reason.
--
-- So the language must be the account holder's, and the request's
-- Accept-Language is not it. When an attacker is the one changing the password,
-- the request carries the ATTACKER's browser language, and the victim receives
-- their warning in a language they may not read. The notice still arrives, still
-- says the right thing, and is useless -- which is worse than not sending it,
-- because the deployment believes the person was told.
--
-- Interactive messages are the opposite case and deliberately do NOT use this
-- column: a sign-in code or an address confirmation is read by the person who
-- just submitted the form, so their request's language is the right one and a
-- stale stored preference would be the wrong one.
--
-- NULL means "no preference recorded", which falls back to the deployment
-- default rather than to whatever the last request happened to carry.
ALTER TABLE core.users ADD COLUMN locale text;

-- A BCP 47 tag, loosely bounded. Not a foreign key to a table of languages:
-- the set of locales a deployment serves is decided by which message catalogues
-- are installed, which is a filesystem fact rather than a database one, and a
-- constraint here would either duplicate it or contradict it.
--
-- The length and shape check is only to keep something that is not a language
-- tag at all out of the column -- an email address, a whole Accept-Language
-- header -- since this value is chosen by a user and ends up selecting a
-- catalogue.
ALTER TABLE core.users ADD CONSTRAINT users_locale_is_a_tag
    CHECK (locale IS NULL OR locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8}){0,3}$');

COMMENT ON COLUMN core.users.locale IS
    'BCP 47 tag for messages this person receives. NULL falls back to the '
    'deployment default. Used for account-security notices, which must be in '
    'the account holder''s language rather than the requesting browser''s.';
