-- 0188_consent_lifetime.sql
--
-- How long a person's consent to an application lasts before they are asked
-- again (5.22).
--
-- A consent, once given, stood until withdrawn: an application approved years
-- ago for a project long finished kept everything it was approved for, and was
-- never put in front of the person again. With this set, a consent older than
-- the client's lifetime counts for nothing at the next authorization, and the
-- consent screen asks afresh, for what is requested now only. NULL is the
-- behaviour before: a consent that does not expire. Tokens already issued keep
-- their own lifetimes.
--
-- Not declared compatible: the bounds are a constraint on a table the release
-- before has, which the declaration refuses.

ALTER TABLE core.clients ADD COLUMN consent_lifetime_s integer
    CONSTRAINT clients_consent_lifetime_bounds
    CHECK (consent_lifetime_s IS NULL OR consent_lifetime_s BETWEEN 3600 AND 315360000);

COMMENT ON COLUMN core.clients.consent_lifetime_s IS
    'Seconds a person''s consent to this client lasts before they are asked again; NULL, never. `signari client set-lifetimes -consent-ttl`, the Admin API''s consent_lifetime_s.';
