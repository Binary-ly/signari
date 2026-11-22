-- 0195_user_handle_any_length.sql
--
-- A user handle of 1 to 64 bytes, as WebAuthn defines one (Web
-- Authentication Level 3, §4 "User Handle", and §5.1.3, which refuses one
-- "not between 1 and 64 bytes"), rather than exactly the 64 this server
-- generates (0.44). An authenticator returns the handle a passkey was registered under,
-- and that handle has to be the account's for either sign-in to accept the
-- passkey. An import gives a person the handle their previous provider
-- registered their passkeys under, and those are other lengths: a handle
-- made from a user's UUID as text is 36 bytes. Handles this server makes are
-- still 64 random bytes.
--
-- Not declared compatible with the release before: it replaces a constraint on
-- a table that release writes, which only an additive migration may do and
-- stay servable by a binary that predates it.

ALTER TABLE core.users DROP CONSTRAINT users_user_handle_check;
ALTER TABLE core.users ADD CONSTRAINT users_user_handle_check
    CHECK (octet_length(user_handle) BETWEEN 1 AND 64);
