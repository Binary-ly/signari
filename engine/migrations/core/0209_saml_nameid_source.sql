-- signari:compatible-with-previous
--
-- 0209_saml_nameid_source.sql
--
-- Where a service provider's NameID comes from, and what format it went out in (8.06).
--
-- name_id_attribute names a declared attribute, or `username`, for a provider that
-- keys its accounts on something an operator already has: an employee number, a
-- sAMAccountName. Unset is what the format alone decides, as before.
--
-- name_id_format on a participant is the format the assertion carried, because a
-- provider matches a LogoutRequest on it, and every LogoutRequest said persistent
-- whatever the assertion had said. Read back from the participant rather than the
-- provider, whose format may have changed since. Empty on a row written before this,
-- which logout reads as persistent, as it always did.

ALTER TABLE core.saml_providers ADD COLUMN name_id_attribute text;

ALTER TABLE core.saml_session_participants ADD COLUMN name_id_format text;
