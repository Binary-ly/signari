-- 0234_more_hooks.sql
--
-- Five more decisions an operator's own service can take part in (10.01): a sign-in about
-- to get a session, an account about to be made, a person about to reach an application,
-- and what userinfo and a SAML assertion say. Each is consulted after this engine has
-- decided yes, so a provider can only take a yes back, and the last two can add what the
-- operator's list lets them. A refresh has no hook of its own: token_issue is asked at
-- every grant, and says so in grant_type.

ALTER TABLE core.providers DROP CONSTRAINT providers_hook_check;
ALTER TABLE core.providers
    ADD CONSTRAINT providers_hook_check
    CHECK (hook IN ('authorize', 'token_issue', 'password_verify', 'authenticate', 'user_create',
                    'client_access', 'userinfo', 'saml_assertion'));
