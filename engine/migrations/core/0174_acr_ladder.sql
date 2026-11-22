-- 0174_acr_ladder.sql
--
-- Two rungs above multi-factor (4.15): "3", multi-factor that includes a
-- WebAuthn assertion, which is bound to this server's origin so a page relaying
-- the sign-in cannot obtain one; and "4", the same with a device-bound key.
-- A client may require either as its floor, and a relying party may ask for
-- either in acr_values.
--
-- A session still records "1" or "2", so an ID token reports what it did
-- before unless the request asked for more. authorization_codes.acr carries
-- the rung a request asked for and was given, for that request's ID token.
--
-- Not compatible with the release before, which reads a floor of "3" or "4"
-- as no multi-factor floor at all.
ALTER TABLE core.clients DROP CONSTRAINT clients_minimum_acr_check;
ALTER TABLE core.clients ADD CONSTRAINT clients_minimum_acr_check
    CHECK (minimum_acr IN ('1', '2', '3', '4'));
ALTER TABLE core.authorization_codes ADD COLUMN acr text CHECK (acr IN ('3', '4'));

COMMENT ON COLUMN core.clients.minimum_acr IS
    'The weakest authentication the client accepts: 1 a single factor, 2 multi-factor, 3 '
    'multi-factor with a WebAuthn assertion (phishing-resistant), 4 the same with a device-bound key. '
    'Set with `signari client set-acr`.';
COMMENT ON COLUMN core.authorization_codes.acr IS
    'The rung above the session''s own that this request asked for in acr_values and was given, '
    'reported by its ID token; NULL reports the session''s.';
