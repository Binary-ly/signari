-- 0297_vp_issuer_metadata.sql
--
-- A wallet sign-in may find a believed issuer's keys in its JWT VC Issuer Metadata
-- (specs/sdjwtvc.txt:1085-1089 and section 3), fetched for each presentation, rather than hold
-- them pinned: keys_from is 'pinned', with jwks, or 'metadata', without. Not compatible with
-- the previous release once an issuer is set the second way: that release reads the missing
-- keys as an error and refuses that wallet sign-in, which fails closed.

ALTER TABLE core.vp_trusted_issuers ALTER COLUMN jwks DROP NOT NULL;

ALTER TABLE core.vp_trusted_issuers
    ADD COLUMN keys_from text NOT NULL DEFAULT 'pinned' CHECK (keys_from IN ('pinned', 'metadata'));

ALTER TABLE core.vp_trusted_issuers
    ADD CONSTRAINT vp_trusted_issuers_keys CHECK ((keys_from = 'pinned') = (jwks IS NOT NULL));

COMMENT ON COLUMN core.vp_trusted_issuers.keys_from IS
    'pinned: the keys in jwks; metadata: the keys the issuer publishes at /.well-known/jwt-vc-issuer';
