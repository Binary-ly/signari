-- 0005_optional_pkce.sql
--
-- Models an authorization code that carries no PKCE challenge.
--
-- The bug this fixes was found by the OIDF conformance suite, and could not have
-- been found by our own tests. 0002 declared:
--
--     code_challenge        text NOT NULL,
--     code_challenge_method text NOT NULL DEFAULT 'S256'
--                           CHECK (code_challenge_method IN ('S256','plain'))
--
-- which encodes an assumption: that every authorization code has PKCE. That is
-- true of every request WE generate, because our clients default to
-- require_pkce = true and every test we wrote therefore sends a challenge.
--
-- It is not true of OIDC Core. PKCE is not mandatory there, and the Basic OP
-- profile exercises the plain authorization code flow. A client configured with
-- require_pkce = false produced an empty-string method, which failed the CHECK
-- and turned the authorize endpoint into a 500.
--
-- Absent PKCE is NULL, not an empty string. The two columns move together: a
-- challenge without a method, or a method without a challenge, is incoherent.

SET search_path = core, public;

ALTER TABLE core.authorization_codes
    ALTER COLUMN code_challenge        DROP NOT NULL,
    ALTER COLUMN code_challenge_method DROP NOT NULL,
    ALTER COLUMN code_challenge_method DROP DEFAULT;

-- Existing rows wrote '' rather than NULL; normalise them so the constraint
-- below can be trusted.
UPDATE core.authorization_codes
SET code_challenge        = NULLIF(code_challenge, ''),
    code_challenge_method = NULLIF(code_challenge_method, '');

ALTER TABLE core.authorization_codes
    DROP CONSTRAINT IF EXISTS authorization_codes_code_challenge_method_check;

-- Both present or both absent. Enforced in the database rather than trusted to
-- the application, because a code with a challenge and no method would verify
-- against nothing.
ALTER TABLE core.authorization_codes
    ADD CONSTRAINT authorization_codes_pkce_is_coherent CHECK (
        (code_challenge IS NULL AND code_challenge_method IS NULL)
        OR
        (code_challenge IS NOT NULL AND code_challenge_method IN ('S256', 'plain'))
    );

COMMENT ON COLUMN core.authorization_codes.code_challenge IS
    'NULL when the client did not use PKCE. Not an empty string -- see 0005.';
