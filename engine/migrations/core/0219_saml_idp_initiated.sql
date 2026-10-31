-- signari:compatible-with-previous
--
-- 0219_saml_idp_initiated.sql
--
-- A sign-in the identity provider starts (8.02), for an application that has no sign-in
-- page of its own to send anybody from, or whose people start from the portal. An
-- unsolicited response answers no request, so a service provider has to expect one, and
-- each is opted in: idp_initiated is false until an operator says otherwise.
--
-- default_relay_state is what goes with the response, usually the page in the application
-- to land on. It is the operator's and never the caller's: taken from the URL, it would
-- let any link choose where a signed-in person lands inside the application.

ALTER TABLE core.saml_providers ADD COLUMN idp_initiated boolean NOT NULL DEFAULT false;
ALTER TABLE core.saml_providers ADD COLUMN default_relay_state text NOT NULL DEFAULT '';
