-- 0224_password_verify_hook.sql
--
-- A password checked by the operator's own service during a migration (10.07, 10.14). A
-- system that speaks neither the OIDC password grant nor LDAP could be left only with an
-- export of its hashes, and many of those cannot be exported or cannot be read here. So
-- the operator runs a small service that can check a password against the old system, and
-- registers it as a provider (ADR-011) for the password_verify hook.
--
-- `hook` is the migration source that says so: it names no endpoint of its own, since
-- the provider holds that, so token_endpoint stays empty for it, as client_id does for
-- ldap.

ALTER TABLE core.providers DROP CONSTRAINT providers_hook_check;
ALTER TABLE core.providers
    ADD CONSTRAINT providers_hook_check
    CHECK (hook IN ('authorize', 'token_issue', 'password_verify'));

ALTER TABLE core.migration_sources DROP CONSTRAINT migration_sources_kind_check;
ALTER TABLE core.migration_sources
    ADD CONSTRAINT migration_sources_kind_check CHECK (kind IN ('oidc_password', 'ldap', 'hook'));

ALTER TABLE core.migration_sources DROP CONSTRAINT migration_sources_shape;
ALTER TABLE core.migration_sources ADD CONSTRAINT migration_sources_shape CHECK (
    (kind = 'oidc_password'
        AND token_endpoint LIKE 'https://%'
        AND client_id IS NOT NULL
        AND bind_dn_template IS NULL AND NOT start_tls AND ca_pem IS NULL)
    OR
    (kind = 'ldap'
        AND bind_dn_template LIKE '%{username}%'
        AND client_id IS NULL AND client_secret_enc IS NULL
        AND (token_endpoint LIKE 'ldaps://%' OR (token_endpoint LIKE 'ldap://%' AND start_tls)))
    OR
    (kind = 'hook'
        AND token_endpoint = ''
        AND client_id IS NULL AND client_secret_enc IS NULL
        AND bind_dn_template IS NULL AND NOT start_tls AND ca_pem IS NULL)
);
