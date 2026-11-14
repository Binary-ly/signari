-- 0298_vp_issuer_x5c.sql
--
-- A wallet sign-in may believe an issuer by the X.509 chain its credentials carry in x5c,
-- validated to root certificates the operator holds for that issuer (specs/sdjwtvc.txt:1091-1098):
-- keys_from 'x5c', with roots, and neither jwks nor a metadata lookup. Not compatible with the
-- previous release once an issuer is set this way: that release reads the missing keys as an
-- error and refuses that wallet sign-in, which fails closed.

ALTER TABLE core.vp_trusted_issuers ADD COLUMN roots text;

ALTER TABLE core.vp_trusted_issuers DROP CONSTRAINT vp_trusted_issuers_keys_from_check;

ALTER TABLE core.vp_trusted_issuers
    ADD CONSTRAINT vp_trusted_issuers_keys_from_check CHECK (keys_from IN ('pinned', 'metadata', 'x5c'));

ALTER TABLE core.vp_trusted_issuers
    ADD CONSTRAINT vp_trusted_issuers_roots CHECK ((keys_from = 'x5c') = (roots IS NOT NULL));

COMMENT ON COLUMN core.vp_trusted_issuers.keys_from IS
    'pinned: the keys in jwks; metadata: the keys the issuer publishes at /.well-known/jwt-vc-issuer; '
    'x5c: the key in the credential''s own certificate chain, validated to roots';

COMMENT ON COLUMN core.vp_trusted_issuers.roots IS
    'PEM root certificates an x5c issuer''s chain must lead to; public, not sealed';
