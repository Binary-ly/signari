-- 0144_client_token_lifetime_bounds.sql
--
-- Bounds on a client's access and refresh token lifetimes, now that they can
-- be set.
--
-- # The defect
--
-- Both columns existed since 0002 with no writer, so every client's access
-- tokens lived five minutes and its refresh tokens thirty days, whatever the
-- console showed. The access lifetime was not even read: every grant minted
-- with the built-in default. `client set-lifetimes`, the client PATCH and
-- `apply` write them now, through store.SetClientSettings, which checks the
-- same bounds.
--
-- # Why the bounds are in the schema as well
--
-- An access token is self-contained and outlives its revocation until it
-- expires (ADR-007), so its lifetime IS the revocation window, and the
-- janitor's sweep of credential offers keeps a margin of tokens.MaxAccessTokenTTL
-- on the assumption that no access token lives longer. That assumption should
-- hold for every writer, including one that has not been written yet. Refresh
-- tokens are revocable and rotated, so their ceiling is a year and their floor
-- is five minutes: below that a refresh token is an access token with extra
-- steps.

SET search_path = core, public;

ALTER TABLE clients
    ADD CONSTRAINT clients_access_token_ttl_bounds
        CHECK (access_token_ttl_s BETWEEN 60 AND 3600),
    ADD CONSTRAINT clients_refresh_token_ttl_bounds
        CHECK (refresh_token_ttl_s BETWEEN 300 AND 31536000);
