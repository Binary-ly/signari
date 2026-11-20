-- signari:compatible-with-previous
--
-- 0306_wsfed_reply_url.sql
--
-- Where each WS-Federation application of a session was sent its token, so that a sign-out can
-- send it the clean-up message (8.09). WS-Federation 1.2 §13.2.4 has the identity provider's STS
-- send clean-up messages to every relying party it issued a token to for the session, each a GET
-- with wa=wsignoutcleanup1.0 (§13.2.4.2), and §13.1.2 asks for them in parallel rather than
-- chained. Null for a sign-in through SAML, which single logout reaches instead. An older binary
-- writes and reads none, and the applications of its sessions are not told of a sign-out, as
-- before this.

ALTER TABLE core.saml_session_participants ADD COLUMN wsfed_reply_url text;
