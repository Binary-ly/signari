-- 0149_drop_access_tokens.sql
--
-- Drops core.access_tokens.
--
-- It was created in 0002 for opaque access tokens, which were never built:
-- every access token this engine mints is a JWT, and nothing ever inserted a
-- row. Its one reader was the count the admin API's user and client deletes
-- reported as tokens_revoked, which was therefore 0 for every delete. Those
-- deletes now count the refresh token families they end. Opaque tokens, if
-- they come, come with the code that mints and introspects them, and a table
-- shaped for that.
--
-- No view reads it. Dropping it takes its row-level policy, its expiry index
-- and its configuration-version trigger with it.

SET search_path = core, public;

DROP TABLE access_tokens;
