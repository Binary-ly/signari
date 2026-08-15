
SET search_path = core, public;

ALTER TABLE core.clients
    -- Which RFC 8705 subject field must match, and to what. Only ONE is set:
    -- matching on several is an AND nobody expects, and matching on any-of is a
    -- weaker check than the operator thinks they configured.
    ADD COLUMN tls_subject_dn text,
    ADD COLUMN tls_san_dns    text,
    ADD COLUMN tls_san_uri    text,

    -- For self_signed_tls_client_auth: SHA-256 of the DER certificate.
    ADD COLUMN tls_thumbprint bytea
        CHECK (tls_thumbprint IS NULL OR length(tls_thumbprint) = 32),

    -- Certificate-bound access tokens. Separate from authentication because a
    -- client may authenticate by certificate and still want plain bearer tokens
    -- during a migration -- and because turning binding ON is the change that
    -- breaks callers who are not ready, so it should be a deliberate flip.
    ADD COLUMN tls_bound_tokens boolean NOT NULL DEFAULT false,

    -- Exactly one authentication method may be configured. Two would leave the
    -- question of which is authoritative to whoever reads the code next.
    ADD CONSTRAINT clients_one_tls_auth_method CHECK (
        (CASE WHEN tls_subject_dn IS NOT NULL THEN 1 ELSE 0 END) +
        (CASE WHEN tls_san_dns    IS NOT NULL THEN 1 ELSE 0 END) +
        (CASE WHEN tls_san_uri    IS NOT NULL THEN 1 ELSE 0 END) +
        (CASE WHEN tls_thumbprint IS NOT NULL THEN 1 ELSE 0 END) <= 1
    );

COMMENT ON COLUMN core.clients.tls_bound_tokens IS
    'Issue certificate-bound access tokens (RFC 8705 §3) to this client. The '
    'cnf.x5t#S256 claim ties the token to the presenting certificate, so a '
    'stolen token is useless without the private key.';

COMMENT ON COLUMN core.clients.tls_thumbprint IS
    'SHA-256 of the DER client certificate, for self_signed_tls_client_auth. '
    'Exact match: a self-signed certificate has no issuer worth trusting, so the '
    'certificate itself is the credential.';
