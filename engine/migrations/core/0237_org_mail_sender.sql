-- signari:compatible-with-previous
--
-- 0237_org_mail_sender.sql
--
-- The address an organisation's mail comes from (10.10), when it is not the deployment's. Both
-- columns are empty until an operator sets them, and an organisation with none keeps sending
-- from SIGNARI_MAIL_FROM. The engine's setter holds the full rule; these hold the shape, since
-- a line break in either would reach a message's headers.

ALTER TABLE core.organizations ADD COLUMN mail_from text CHECK (mail_from ~ '^[^@[:space:][:cntrl:]]+@[^@[:space:][:cntrl:]]+$');
ALTER TABLE core.organizations ADD COLUMN mail_from_name text CHECK (mail_from_name !~ '[[:cntrl:]]');
