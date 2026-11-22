-- 0235_flow_condition_hook.sql
--
-- A sign-in flow that branches on what only the operator's own service knows (10.02). A
-- `when:` is one of a closed list, so a flow can be walked and proved, and that stays true:
-- `provider_condition` is one more name on the list, and what answers it is a hook.
-- It can also say what the language has always named and nothing could answer: whether the
-- device is managed and compliant, whether the network is trusted.

ALTER TABLE core.providers DROP CONSTRAINT providers_hook_check;
ALTER TABLE core.providers
    ADD CONSTRAINT providers_hook_check
    CHECK (hook IN ('authorize', 'token_issue', 'password_verify', 'authenticate', 'user_create',
                    'client_access', 'userinfo', 'saml_assertion', 'flow_condition'));
