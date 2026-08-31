-- Which authenticators an organisation will accept.
--
-- # Attestation is OFF by default, and that is a decision
--
-- Requesting attestation conveyance sends the authenticator's attestation
-- statement, which identifies the device model and, for some vendors, a batch.
-- The WebAuthn specification and every browser vendor made `none` the default
-- deliberately: it is the privacy-preserving choice, and some browsers show the
-- user an extra prompt when a site asks for more.
--
-- An enterprise that must know "only these approved hardware keys" has a real
-- need and turns this on. A deployment that does not have that need should not
-- be collecting device identifiers from its users by accident, so the default
-- stays `none`.
--
-- # An AAGUID from a `none` registration is SELF-ASSERTED
--
-- This is the part that makes the allow-list meaningful or meaningless. With
-- conveyance `none` the authenticator data still carries an AAGUID, and nothing
-- vouches for it — a software authenticator can claim to be a YubiKey by
-- putting Yubico's AAGUID in the field. Filtering on it would be theatre: the
-- value being filtered is chosen by the party being filtered.
--
-- So `allowed_aaguids` is enforced ONLY when attestation was actually conveyed
-- and the statement verified. A policy that names an allow-list without raising
-- the conveyance is refused, rather than silently applied to a value the client
-- chose.
--
-- # What verification does and does not prove here
--
-- With conveyance raised, the library verifies the attestation statement's
-- format and signature. It does NOT validate the attestation certificate to a
-- FIDO Metadata Service root, because this deployment has no MDS attestation
-- roots — `internal/fidomds` maps AAGUIDs to model names and carries no
-- certificates.
--
-- The honest description: an allow-list stops a casual software authenticator,
-- which cannot produce a well-formed packed attestation for a hardware vendor's
-- AAGUID, and does not stop somebody who obtains a genuine attestation key. It
-- is a real control with a stated ceiling, and the ceiling is written here so
-- nobody builds a compliance claim on top of it.

CREATE TABLE core.webauthn_policy (
    org_id      uuid        PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- What to ask the browser for. The WebAuthn values.
    attestation_conveyance text NOT NULL DEFAULT 'none'
                            CHECK (attestation_conveyance IN ('none','indirect','direct','enterprise')),

    -- Empty means every authenticator is acceptable.
    --
    -- Stored as uuid[] rather than text so a malformed AAGUID is refused by the
    -- database rather than silently never matching -- an allow-list entry that
    -- can never match is an allow-list that is quietly denying everything.
    allowed_aaguids uuid[]  NOT NULL DEFAULT '{}',

    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now(),

    -- An allow-list is only meaningful when the AAGUID is vouched for. See the
    -- header: with conveyance `none` the value is chosen by the authenticator
    -- being filtered, so filtering on it would be theatre.
    CONSTRAINT webauthn_allow_list_needs_attestation
        CHECK (cardinality(allowed_aaguids) = 0 OR attestation_conveyance <> 'none')
);

-- Whether the credential's AAGUID was vouched for at registration.
--
-- Recorded per credential rather than inferred from the organisation's current
-- policy, because policy changes and this fact does not: a credential registered
-- under `none` has a self-asserted AAGUID forever, and a later policy raising
-- conveyance must not retroactively make it trustworthy.
ALTER TABLE core.webauthn_credentials
    ADD COLUMN attestation_verified boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.webauthn_credentials.attestation_verified IS
    'true when attestation was conveyed and verified at registration, so the '
    'aaguid is vouched for. false means the aaguid is self-asserted and must '
    'not be used for policy.';

ALTER TABLE core.webauthn_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.webauthn_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY webauthn_policy_org_isolation ON core.webauthn_policy
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
