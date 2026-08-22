SET search_path = core, public;

-- OpenID Federation 1.0 (Final, 17 February 2026), Trust Marks: sections 7, 8.4,
-- 8.5 and 8.6.
--
-- # What a Trust Mark answers that a Trust Chain does not
--
-- A Trust Chain proves provenance: this entity is who it says it is and an
-- authority above it vouches for its keys. It says nothing about CONFORMANCE --
-- whether the entity has been assessed against a framework and passed. That is
-- what a Trust Mark is, and it is why a federation can have a perfectly valid
-- chain to a relying party it must not admit.
--
-- # Why the signed JWT is stored rather than re-minted on request
--
-- Section 8.6 serves the mark verbatim, and section 8.4's status endpoint is
-- asked about ONE mark -- the exact JWT a stranger presents. Re-minting per
-- request would give every response a fresh `iat`, so the mark a subject
-- published in its own Entity Configuration would never be byte-identical to the
-- one we would serve or recognise, and the status endpoint could not answer at
-- all: it would have nothing to compare against.
--
-- So the mark is an artefact with an identity, and revocation is a state change
-- on that artefact rather than a decision recomputed each time.

-- Trust Marks THIS instance has issued, as a Trust Mark Issuer.
CREATE TABLE federation_trust_marks_issued (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES core.instances(id) ON DELETE CASCADE,

    -- Section 7.1: "The Trust Mark type identifier MUST be collision-resistant
    -- across multiple federations. It is RECOMMENDED that the identifier value
    -- is built using a URL".
    trust_mark_type text NOT NULL CHECK (trust_mark_type <> ''),

    -- The Entity Identifier the mark is about: the `sub` claim.
    subject text NOT NULL CHECK (subject LIKE 'https://%'),

    -- The compact serialisation, exactly as signed and exactly as served.
    trust_mark text NOT NULL CHECK (trust_mark <> ''),

    -- SHA-256 of the compact serialisation.
    --
    -- The status endpoint (8.4.1) is handed a whole Trust Mark and must decide
    -- whether it issued THAT one. Looking it up by (type, subject) would answer
    -- about a different artefact with the same coordinates -- a superseded mark,
    -- or a forgery with matching claims -- and report it active. Section 8.4.2's
    -- `invalid` status exists precisely for "another error was detected", and
    -- distinguishing the cases needs an identity for the bytes.
    trust_mark_hash bytea NOT NULL UNIQUE CHECK (length(trust_mark_hash) = 32),

    -- Section 7.1 makes `exp` OPTIONAL: "If not present, it means that the Trust
    -- Mark does not expire." NULL is that case, and it is not the same as a
    -- distant expiry -- section 7.3's expiry step becomes vacuous, and the only
    -- way a reader learns the mark was withdrawn is the status endpoint.
    expires_at timestamptz,

    -- Section 8.4.2's status vocabulary, minus the two a stored row cannot be.
    --
    -- `expired` is derived from expires_at, not stored: a row whose status said
    -- `active` while its exp had passed would be two facts disagreeing, and the
    -- one that gets read would depend on which query ran. `invalid` is a
    -- property of a submitted document, never of an issued one.
    status text NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'revoked')),
    revoked_at timestamptz,
    revocation_reason text,

    CONSTRAINT trust_mark_revocation_is_dated
        CHECK ((status = 'revoked') = (revoked_at IS NOT NULL)),

    issued_at timestamptz NOT NULL DEFAULT now()
);

-- One live mark per (type, subject), and history retained.
--
-- A partial unique index rather than a plain one: re-issuing a mark after
-- revocation is ordinary -- an entity is reassessed and passes -- and a full
-- unique constraint would force deleting the revoked row, which is the record of
-- why it was withdrawn. Two ACTIVE marks of one type for one subject is the case
-- that must not happen: section 8.6 would have to choose between them.
CREATE UNIQUE INDEX federation_trust_marks_one_active
    ON federation_trust_marks_issued (instance_id, trust_mark_type, subject)
    WHERE status = 'active';

-- Section 8.5 filters by type and optionally by subject.
CREATE INDEX federation_trust_marks_listing
    ON federation_trust_marks_issued (instance_id, trust_mark_type, subject)
    WHERE status = 'active';

-- No row-level security, deliberately, and this is the one place to say why.
--
-- Every org-scoped table in this schema carries ENABLE, FORCE and a policy of
-- `core.is_engine() OR org_id = core.current_org_id()`, and a standing test
-- names any that does not. This table is keyed on the INSTANCE, like
-- federation_config above it: a federation identity belongs to the issuer as a
-- whole and there is no tenant column to isolate on. A policy of `USING (true)`
-- would satisfy a reader glancing for the four familiar lines while isolating
-- nothing, which is worse than their absence.
GRANT SELECT ON federation_trust_marks_issued TO signari_maintenance;

COMMENT ON TABLE federation_trust_marks_issued IS
    'OpenID Federation 1.0 Trust Marks issued by this entity. Serves the trust mark, status and listing endpoints of sections 8.4 to 8.6.';

-- Trust Marks issued TO this entity by others, published in our own Entity
-- Configuration's `trust_marks` claim (section 3.1.2).
--
-- A separate table rather than a `direction` column on the one above. The two
-- have almost nothing in common: one is an artefact we are accountable for and
-- can revoke, the other is somebody else's assertion that we merely republish
-- and whose status we can only ask about. Merging them would put "can I revoke
-- this" behind a column check on every query that matters.
CREATE TABLE federation_trust_marks_held (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    instance_id uuid NOT NULL REFERENCES core.instances(id) ON DELETE CASCADE,

    trust_mark_type text NOT NULL CHECK (trust_mark_type <> ''),
    trust_mark text NOT NULL CHECK (trust_mark <> ''),

    -- The issuer, read out of the mark when it was accepted. Recorded so an
    -- operator listing what we publish can see who vouched for what without
    -- decoding a JWT by hand.
    issuer text NOT NULL CHECK (issuer LIKE 'https://%'),
    expires_at timestamptz,

    added_at timestamptz NOT NULL DEFAULT now(),

    -- Section 3.1.2's array may carry more than one mark of a type from
    -- different issuers, so the identity is the triple.
    UNIQUE (instance_id, trust_mark_type, issuer)
);

-- Instance-keyed; see the note on the issued table above.
GRANT SELECT ON federation_trust_marks_held TO signari_maintenance;

COMMENT ON TABLE federation_trust_marks_held IS
    'Trust Marks other issuers have granted this entity, republished in the trust_marks claim of our Entity Configuration.';

-- The Trust Anchor's two governing claims, section 3.1.2.
--
-- Both are objects keyed by Trust Mark type identifier, so both are jsonb rather
-- than a modelled table: their shape is fixed by the specification, they are
-- written whole by an operator and read whole into an Entity Configuration, and
-- a normalised version would be reassembled into exactly this on every read.
ALTER TABLE federation_config
    ADD COLUMN trust_mark_issuers jsonb,
    ADD COLUMN trust_mark_owners  jsonb;

-- Both claims are meaningless anywhere but a Trust Anchor.
--
-- Section 3.1.2, of each: "This Claim MUST be ignored if present in an Entity
-- Configuration for an Entity that is not a Trust Anchor."
--
-- A Trust Anchor with no Superiors is exactly an entity with no authority_hints
-- -- the same section makes that claim REQUIRED for anything that has one. So
-- the constraint is expressible, and expressing it is worth doing: an operator
-- who sets these on a subordinate has written down a federation policy that
-- every reader is required to discard, and would have no way of finding out.
ALTER TABLE federation_config
    ADD CONSTRAINT federation_trust_mark_claims_need_an_anchor
    CHECK (authority_hints IS NULL
           OR (trust_mark_issuers IS NULL AND trust_mark_owners IS NULL));

COMMENT ON COLUMN federation_config.trust_mark_issuers IS
    'Section 3.1.2. Which issuers this Trust Anchor accepts per Trust Mark type. An EMPTY array against a type means anyone may issue it -- the specification says so, and it is the opposite of the fail-closed reading used elsewhere in this schema.';
COMMENT ON COLUMN federation_config.trust_mark_owners IS
    'Section 3.1.2. Trust Mark types owned by an entity other than their issuer, with the owner keys that validate a delegation.';
