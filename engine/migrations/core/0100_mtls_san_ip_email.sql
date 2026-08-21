SET search_path = core, public;

-- The two RFC 8705 §2.1 subject forms this engine could not express.
--
-- The specification defines five metadata parameters for `tls_client_auth`, of
-- which a client "uses exactly one": `tls_client_auth_subject_dn`,
-- `tls_client_auth_san_dns`, `tls_client_auth_san_uri`,
-- `tls_client_auth_san_ip` and `tls_client_auth_san_email`. Three were
-- implemented. A client whose certificate identifies it by IP address or by
-- email address therefore could not be registered at all -- it fell through to
-- "no usable mutual-TLS expectation is registered", which is honest and is still
-- a client that cannot use a method the RFC defines.
--
-- iPAddress SANs are not exotic in the deployments this matters for: service
-- meshes and appliance certificates frequently carry one and nothing else.
ALTER TABLE clients
    ADD COLUMN tls_san_ip    text,
    ADD COLUMN tls_san_email text;

-- The "exactly one" rule, extended. Rewritten rather than added to, because the
-- rule is a single count and expressing it as two constraints would let a row
-- satisfy each separately while carrying two expectations.
ALTER TABLE clients DROP CONSTRAINT clients_one_tls_auth_method;
ALTER TABLE clients ADD CONSTRAINT clients_one_tls_auth_method
    CHECK (
        (CASE WHEN tls_subject_dn  IS NOT NULL THEN 1 ELSE 0 END
       + CASE WHEN tls_san_dns     IS NOT NULL THEN 1 ELSE 0 END
       + CASE WHEN tls_san_uri     IS NOT NULL THEN 1 ELSE 0 END
       + CASE WHEN tls_san_ip      IS NOT NULL THEN 1 ELSE 0 END
       + CASE WHEN tls_san_email   IS NOT NULL THEN 1 ELSE 0 END
       + CASE WHEN tls_thumbprint  IS NOT NULL THEN 1 ELSE 0 END) <= 1
    );

COMMENT ON COLUMN clients.tls_san_ip IS
    'RFC 8705 tls_client_auth_san_ip: the iPAddress SAN the client certificate '
    'must carry. Compared as a parsed address, never as text.';
COMMENT ON COLUMN clients.tls_san_email IS
    'RFC 8705 tls_client_auth_san_email: the rfc822Name SAN the client '
    'certificate must carry.';
