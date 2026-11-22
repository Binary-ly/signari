-- 0242_migration_source_kerberos.sql
--
-- A Kerberos realm as where a person's password is checked (8.11). The verifier was built and
-- tested and nothing called it, so a person signing in with the password their realm knows was
-- checked locally, where they had none. It joins the sources a password is delegated to, whose
-- throttling and outage handling it needs, and differs in one way: the realm stays the authority,
-- so no hash is taken and a person stays `pending` for as long as the source is there. The realm
-- is held in token_endpoint, the column that says where a source is reached.

ALTER TABLE core.migration_sources DROP CONSTRAINT migration_sources_kind_check;
ALTER TABLE core.migration_sources
    ADD CONSTRAINT migration_sources_kind_check CHECK (kind IN ('oidc_password', 'ldap', 'hook', 'kerberos'));

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
    OR
    (kind = 'kerberos'
        AND token_endpoint <> ''
        AND client_id IS NULL AND client_secret_enc IS NULL
        AND bind_dn_template IS NULL AND NOT start_tls AND ca_pem IS NULL)
);
