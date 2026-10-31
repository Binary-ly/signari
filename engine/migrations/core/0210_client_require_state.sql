-- signari:compatible-with-previous
--
-- 0210_client_require_state.sql
--
-- A client held to sending `state` (9.13). PKCE protects the code here by default, so
-- the parameter is optional, and a relying party whose own CSRF defence is `state` has
-- no way to learn it stopped sending one. Off by default, since turning it on refuses
-- a client that has not been changed.

ALTER TABLE core.clients ADD COLUMN require_state boolean NOT NULL DEFAULT false;
