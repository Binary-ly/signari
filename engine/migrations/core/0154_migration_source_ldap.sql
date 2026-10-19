-- 0154_migration_source_ldap.sql
--
-- A migration source can be the directory being migrated from, not only an
-- OAuth provider's password grant.
--
-- The verifier for an LDAP bind existed (internal/delegated/ldapbind.go) with
-- nothing able to configure it: the kind CHECK admitted only 'oidc_password',
-- and there was nowhere to keep the bind DN template, whether to StartTLS, or
-- the directory's CA. Nothing could create a source of either kind, either;
-- `signari migration-source` and the Admin API now can (2.01).
--
-- The shape CHECK states per kind what the verifier enforces, so a row written
-- by hand cannot be the downgrade the verifier refuses: a password grant only
-- over https and with a client id; a directory only over ldaps:// or ldap://
-- with StartTLS, with {username} in the DN template, and with no OAuth client.

SET search_path = core, public;

ALTER TABLE core.migration_sources DROP CONSTRAINT migration_sources_kind_check;
ALTER TABLE core.migration_sources
    ADD CONSTRAINT migration_sources_kind_check CHECK (kind IN ('oidc_password', 'ldap'));

ALTER TABLE core.migration_sources ALTER COLUMN client_id DROP NOT NULL;

ALTER TABLE core.migration_sources
    ADD COLUMN bind_dn_template text,
    ADD COLUMN start_tls boolean NOT NULL DEFAULT false,
    -- PEM of the CA the directory's certificate must chain to. Absent, the
    -- system roots and SIGNARI_CA_BUNDLE apply.
    ADD COLUMN ca_pem text;

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
);

COMMENT ON COLUMN core.migration_sources.token_endpoint IS
    'Where the source is reached: the token endpoint of an oidc_password source, the ldaps:// or ldap:// URL of an ldap one.';
COMMENT ON COLUMN core.migration_sources.bind_dn_template IS
    'ldap: the DN a user binds as, with {username} replaced by the escaped identifier they typed.';
