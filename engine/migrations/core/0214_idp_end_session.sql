-- signari:compatible-with-previous
--
-- 0214_idp_end_session.sql
--
-- Where to send a browser to sign out at an upstream provider too (8.18). Absent, a
-- sign-out here ends the session here, as it always has, and a person who signed in
-- through a company's provider is still signed in there, so the next sign-in here
-- goes straight through without asking them anything.

ALTER TABLE core.identity_providers ADD COLUMN end_session_url text;
