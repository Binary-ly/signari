-- signari:compatible-with-previous
--
-- 0211_idp_login_domains.sql
--
-- The address domains a provider signs in (8.20), so somebody at corp.example reaches
-- the company's identity provider without being shown a password box first. A routing
-- hint and nothing more: it decides where a person is sent, never who they are, and a
-- local password in the same domain goes on working, or the one account that survives
-- an outage at the provider could not sign in.

ALTER TABLE core.identity_providers ADD COLUMN login_domains text[] NOT NULL DEFAULT '{}';
