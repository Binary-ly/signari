-- signari:compatible-with-previous
--
-- 0221_refresh_reuse_grace.sql
--
-- A retry of a refresh whose answer was lost (9.17). A refresh token is good once, and a
-- second use is taken for theft and ends the whole lineage, which is right and which also
-- signs somebody out when a phone loses signal between the server answering and the
-- application hearing it. refresh_reuse_grace_s lets a client opt in to one retry, within
-- at most thirty seconds, answered with the successor it already should have had. 0, the
-- default, is the old behaviour exactly.
--
-- successor_sealed is that successor, sealed under a key derived from the token it
-- replaced, and written only for a client that opted in. So a read of this table gives
-- nobody a working token: opening it takes the old token, which is not stored here either.
-- Clearing it is what spends the one retry.

ALTER TABLE core.clients ADD COLUMN refresh_reuse_grace_s integer NOT NULL DEFAULT 0;
ALTER TABLE core.refresh_tokens ADD COLUMN successor_sealed bytea;
