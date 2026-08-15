-- Drop email_otp_credentials.enrolled_at.
--
-- The table was created with both `enrolled_at` and `created_at`, each
-- DEFAULT now(), recording the same moment. Nothing read either one, and the
-- unread-column sweep in docs/security-scanning.md caught it the same day.
--
-- Dropped rather than wired up to something: two columns holding the same fact
-- is a question about which one is authoritative, asked of everybody who reads
-- the schema afterwards. `created_at` is the convention everywhere else here.
ALTER TABLE core.email_otp_credentials DROP COLUMN enrolled_at;
