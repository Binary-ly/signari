-- signari:compatible-with-previous
-- 0271_require_signed_request_object.sql
--
-- A client that may start an authorization only with a signed Request Object (RFC
-- 9101 §10.5). Without it the signature is optional, and anybody who can reach the
-- authorization endpoint simply sends the same request unsigned.

ALTER TABLE core.clients ADD COLUMN require_signed_request_object boolean NOT NULL DEFAULT false;
