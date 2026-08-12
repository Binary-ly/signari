-- 0010_first_party_clients.sql
--
-- Marks the clients that may skip the consent screen.
--
-- Consent exists so a user can see what a third party is being given access to.
-- Showing that screen for an organisation's OWN application is theatre: the user
-- is signing in to that application, on its own login page, and "Acme wants to
-- access your Acme account" teaches people to click through consent prompts
-- without reading them -- which is precisely the habit the screen depends on
-- them not having.
--
-- So it is a per-client property, defaulting to FALSE. Defaulting to true would
-- mean a client registered by an operator who never saw this column silently
-- skips consent, and the safe direction is to ask when unsure.
--
-- It does NOT skip anything else: scope validation, redirect matching, PKCE and
-- the acr requirement all still apply. It only suppresses a question whose
-- answer is already implied.

SET search_path = core, public;

ALTER TABLE clients
    ADD COLUMN first_party boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN clients.first_party IS
    'Skips the consent screen. Only for applications belonging to the same organisation as the IdP.';
