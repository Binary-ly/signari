-- 0138_ssf_source_audience_global.sql
--
-- A Shared Signals source is chosen by its issuer and its audience together,
-- and that pair belongs to one organisation in the whole deployment.
--
-- # The defect
--
-- ssf_sources was UNIQUE (org_id, issuer), and the receiver found the source
-- for an incoming token by issuer alone, taking whichever row came back first.
-- Two tenants can trust one transmitter -- a shared upstream issues every
-- customer's events under one issuer and tells them apart by audience -- so
-- the second tenant's events were verified against the first tenant's source.
-- With different audiences they were refused and that tenant received
-- nothing; with the same audience they verified, and the subject was resolved
-- in the first tenant's directory, which signed out somebody else's people.
--
-- # Why unique rather than checked at receive
--
-- The audience is what the transmitter writes to say whom an event is for. A
-- pair two organisations both registered names nobody in particular, and no
-- check at receive time can recover which of them the transmitter meant. As
-- 0129, 0130 and 0134, the second registration is refused where it is made.
--
-- Compared case-insensitively, because the receiver's audience check is.
--
-- # Why the migration refuses rather than chooses
--
-- Which tenant keeps a pair held by two is the operator's decision, and one of
-- them may have been acting on the other's events.

SET search_path = core, public;

DO $$
DECLARE
    duplicates text;
BEGIN
    SELECT string_agg(format('%s for %s (organisations %s)', iss, aud, orgs), '; ')
      INTO duplicates
      FROM (SELECT issuer AS iss, lower(audience) AS aud,
                   string_agg(org_id::text, ', ' ORDER BY created_at) AS orgs
              FROM core.ssf_sources
             GROUP BY issuer, lower(audience)
            HAVING count(*) > 1) d;
    IF duplicates IS NOT NULL THEN
        RAISE EXCEPTION 'a shared-signals issuer and audience must belong to one organisation, '
            'because the receiver chooses the source by that pair; these are registered by '
            'more than one: %', duplicates
            USING HINT = 'Give each organisation''s source the audience its transmitter writes '
                'for that organisation, or remove all but the rightful owner''s, and run the '
                'migration again.';
    END IF;
END $$;

-- The per-organisation constraint stays: `ssf add-source` upserts on it.
CREATE UNIQUE INDEX ssf_sources_issuer_audience_key
    ON core.ssf_sources (issuer, lower(audience));
