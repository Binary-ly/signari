-- 0137_public_client_pkce.sql
--
-- A public client requires PKCE, in the schema as well as in the writers.
--
-- # The defect
--
-- The Admin API and `signari client set-pkce` refused a public client without
-- PKCE, but `signari client create -public -require-pkce=false` made one, and
-- nothing in the schema stopped it. A public client holds no secret, so the
-- PKCE challenge is the only proof that the authorization code reached the
-- application that asked for it; without it, a code intercepted on the way
-- back is a code anybody can redeem.
--
-- # Why the migration refuses rather than chooses
--
-- Requiring PKCE of an existing client that never sends a challenge breaks
-- that integration at its next sign-in. Which of the two it should be -- PKCE
-- turned on, or a confidential client with a secret -- is the operator's
-- decision, so the migration names the clients and stops.

SET search_path = core, public;

DO $$
DECLARE
    offenders text;
BEGIN
    SELECT string_agg(client_id, ', ' ORDER BY client_id)
      INTO offenders
      FROM core.clients
     WHERE client_type = 'public' AND NOT require_pkce;
    IF offenders IS NOT NULL THEN
        RAISE EXCEPTION 'public clients must require PKCE, and these do not: %', offenders
            USING HINT = 'For each: signari client set-pkce -client-id <id> -require-pkce=true '
                '(or register it again as a confidential client), then run the migration again.';
    END IF;
END $$;

ALTER TABLE core.clients
    ADD CONSTRAINT clients_public_requires_pkce
        CHECK (client_type <> 'public' OR require_pkce);
