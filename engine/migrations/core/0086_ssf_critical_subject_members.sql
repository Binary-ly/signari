-- Shared Signals Framework 1.0 §3.6 and §7.1: critical subject members.
--
-- §7.1 lets a Transmitter publish `critical_subject_members` in its
-- configuration metadata: "An array of member names in a Complex Subject which,
-- if present in a Subject Member in an event, MUST be interpreted by a
-- Receiver."
--
-- §3.6 then makes the consequence a MUST on us:
--
--	"An SSF Receiver MUST discard any event that contains a Subject with a
--	Critical member that it is unable to process."
--
-- # Why this is not cosmetic
--
-- The members we understand are `format`, `iss`, `sub` and `email` -- enough to
-- answer "which account". A transmitter that marks, say, a `device` or `tenant`
-- member critical is saying the event is scoped NARROWER than the account, and
-- that acting on it without reading that member is acting on the wrong thing.
--
-- Ignoring it does not fail loudly. A session-revocation event scoped to one
-- device would be applied to every session the user has, and the receiver would
-- have no way to know it had over-applied. That is the same silent-widening
-- shape as the token-lifecycle defects: nothing errors, and the blast radius is
-- wrong.
--
-- Stored per source rather than fetched live from transmitter metadata, for the
-- same reason `allowed_events` is: what this receiver will act on is a local
-- decision, and letting a remote document widen or narrow it at request time
-- makes the security posture depend on somebody else's uptime and honesty.
ALTER TABLE core.ssf_sources
    ADD COLUMN critical_subject_members text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN core.ssf_sources.critical_subject_members IS
    'SSF 1.0 section 3.6 / 7.1: subject member names this transmitter marks Critical. An event whose subject carries one of these that we cannot process is discarded rather than acted on with the wrong scope.';
