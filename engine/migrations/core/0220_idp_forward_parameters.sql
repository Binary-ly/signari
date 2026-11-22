-- signari:compatible-with-previous
--
-- 0220_idp_forward_parameters.sql
--
-- What a sign-in here passes on to the provider it goes through (8.36). A request that
-- asked for a fresh sign-in or a second factor went upstream saying neither, so a
-- provider that would have done it was never asked, and the person met a second prompt
-- here instead, or none at all.
--
-- Opted in per provider, empty until an operator names some: what an application asks of
-- a sign-in is not every provider's business.

ALTER TABLE core.identity_providers ADD COLUMN forward_parameters text[] NOT NULL DEFAULT '{}';
