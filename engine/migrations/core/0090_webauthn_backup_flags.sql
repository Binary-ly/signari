-- 0090_webauthn_backup_flags.sql
--
-- Carry WebAuthn backup eligibility and backup state on each credential.
--
-- # The bug this fixes
--
-- WebAuthn Level 3 §6.1.3: "The value of the BE flag is set during
-- authenticatorMakeCredential operation and MUST NOT change." go-webauthn
-- enforces it by comparing the asserted BE flag against the one on the
-- credential the relying party supplies, and refusing the login if they differ.
--
-- We supplied a credential with no flags set, so BE was false for every
-- credential this server loaded. A synced passkey asserts BE=1. The comparison
-- failed and the assertion was refused -- meaning an iCloud Keychain, Google
-- Password Manager, Windows Hello or 1Password passkey could be REGISTERED
-- successfully and then never used to sign in.
--
-- # The second bug, and why this migration can repair the data
--
-- store.SaveCredential's fifth-from-last parameter is `discoverable bool` and
-- writes to is_discoverable. The registration handler passed
-- `cred.Flags.BackupEligible` into that position. So is_discoverable does not
-- hold discoverability -- it holds backup eligibility, under a column named for
-- something else. Positional arguments of the same type, two adjacent booleans.
--
-- That mistake is what makes the repair possible: the value we need was being
-- written all along, just to the wrong column.
--
--   backup_eligible := is_discoverable   -- recovering what was actually stored
--   is_discoverable := true              -- see below
--
-- Setting is_discoverable to true for every existing row is not a guess.
-- BeginRegistration passes ResidentKey: ResidentKeyRequirementRequired, so every
-- credential this server has ever created is discoverable. The column was
-- carrying the wrong fact; the right one is a constant for our data.
--
-- backup_state has never been recorded and starts false. That is safe: BE=1/BS=0
-- is a valid combination (a multi-device credential not currently backed up),
-- nothing compares the stored BS against an assertion, and the true value is
-- written on the next successful login.

SET search_path = core, public;

ALTER TABLE webauthn_credentials
    ADD COLUMN backup_eligible boolean NOT NULL DEFAULT false,
    ADD COLUMN backup_state    boolean NOT NULL DEFAULT false;

UPDATE webauthn_credentials SET backup_eligible = is_discoverable;
UPDATE webauthn_credentials SET is_discoverable = true;

COMMENT ON COLUMN webauthn_credentials.backup_eligible IS
    'WebAuthn L3 BE flag. Immutable after registration (§6.1.3); the login path '
    'compares the asserted flag against this one and refuses a mismatch.';
COMMENT ON COLUMN webauthn_credentials.backup_state IS
    'WebAuthn L3 BS flag, as of the most recent ceremony. §6.1.3 RECOMMENDS '
    'storing it; a 1->0 transition means a credential is no longer backed up.';
