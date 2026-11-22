-- signari:compatible-with-previous
--
-- 0225_outpost_version.sql
--
-- What an outpost is running (8.31). last_seen_at said it had called and nothing said what
-- called, while an outpost older than its core loses what it does not know to ask for
-- without saying so: one that predates bind proofs binds and cannot search. Each call now
-- says, and last_seen_version keeps the latest. NULL is an outpost that never has.

ALTER TABLE core.outposts ADD COLUMN last_seen_version text;
