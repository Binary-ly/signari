-- RFC 8705 §4: bind a public client's refresh token to its certificate.
--
--	"When the authorization server issues a refresh token to such a client, it
--	SHOULD also bind the refresh token to the respective certificate and check
--	the binding when the refresh token is presented to get new access tokens."
--
-- The same seam migration 0083 closed for DPoP, in the mutual-TLS half of the
-- product. "Such a client" is §4's public client: one that presents a
-- certificate to get certificate-BOUND tokens without using that certificate to
-- authenticate. §7.1 explains why confidential clients need nothing here --
-- `tls_client_auth` makes them "indirectly certificate-bound by way of the
-- client ID and the associated requirement for (certificate-based)
-- authentication" -- so the binding is enforced for public clients only, exactly
-- as with DPoP.
--
-- A SHOULD rather than a MUST, and implemented anyway: the alternative is
-- issuing a certificate-bound access token from a refresh token that anybody
-- could present, which advertises a constraint the grant does not keep.
ALTER TABLE core.refresh_token_families ADD COLUMN cert_thumbprint text;

COMMENT ON COLUMN core.refresh_token_families.cert_thumbprint IS
    'RFC 8705 §4 refresh token binding: the certificate thumbprint the lineage is bound to. Enforced for public clients at every rotation; null when the family was not established over a client certificate.';
