
SET search_path = core, public;

ALTER TABLE identity_providers
    ADD COLUMN trust_email_verification boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN identity_providers.trust_email_verification IS
    'Generic OIDC only: believe this provider''s email_verified claim. Ignored for google/github/microsoft, whose policy is decided in code.';
