-- signari:compatible-with-previous
-- 0262_kerberos_trust_and_accounts.sql
--
-- Two opt-ins on a Kerberos realm (8.12), both off, so a realm registered before this behaves as it
-- did. Trusted realms are the others whose people may sign in: a ticket from one is refused unless it
-- is named here, whatever trust the KDCs have between them. Creating accounts lets a principal with a
-- good ticket and no account have one, asked of the user_create hook first. An older binary reads
-- neither, and so refuses a trusted realm's tickets and creates nothing, as it always did.

ALTER TABLE core.kerberos_realms ADD COLUMN trusted_realms text[] NOT NULL DEFAULT '{}';
ALTER TABLE core.kerberos_realms ADD COLUMN create_accounts boolean NOT NULL DEFAULT false;
