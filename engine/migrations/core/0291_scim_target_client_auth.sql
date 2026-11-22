-- signari:compatible-with-previous
--
-- 0291_scim_target_client_auth.sql
--
-- How a SCIM target's client authenticates at its token endpoint (7.14): HTTP Basic, as
-- before and the default, or the id and secret in the form, for a token endpoint that
-- takes only that. Compatible with the previous release, which ignores the column and
-- goes on sending Basic: a target set to the form is then refused by its token
-- endpoint until that node is upgraded, and nothing is sent anywhere it should not be.

ALTER TABLE core.scim_targets
    ADD COLUMN oauth_client_auth text NOT NULL DEFAULT 'client_secret_basic'
        CHECK (oauth_client_auth IN ('client_secret_basic', 'client_secret_post'));

COMMENT ON COLUMN core.scim_targets.oauth_client_auth IS
    'client_secret_basic (RFC 6749 2.3.1''s required method) or client_secret_post, for a target''s token endpoint';
