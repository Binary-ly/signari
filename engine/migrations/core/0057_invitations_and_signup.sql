-- Getting a new person an account.
--
-- Until now the only route was an administrator running `signari user create`,
-- or just-in-time provisioning through a federated provider. Neither covers the
-- ordinary case: someone joins and needs an account they set the password on
-- themselves, without an administrator learning that password.

-- An invitation to create one account.
--
-- Single use, expiring, and optionally bound to an email address. The binding
-- matters: an unbound invitation that leaks is an account in the organisation
-- for whoever found it, and invitations leak the way every emailed link leaks --
-- forwarded threads, shared mailboxes, corporate mail scanners that follow URLs.
CREATE TABLE core.invitations (
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The token is never stored. A database read must not yield working
    -- invitations, for the same reason it must not yield working passwords.
    token_hash bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),

    -- When set, only this address may accept. Left null for a link that anyone
    -- holding it may use, which is sometimes what is wanted and is always worth
    -- being a deliberate choice.
    email      text,

    -- Groups the new account joins. This is why an invitation is more than a
    -- signup link: it carries the authorisation decision that was made when
    -- somebody decided to invite this person.
    grant_groups text[] NOT NULL DEFAULT '{}',

    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES core.users(id) ON DELETE SET NULL,

    used_at    timestamptz,
    used_by    uuid REFERENCES core.users(id) ON DELETE SET NULL,
    revoked_at timestamptz,

    CONSTRAINT invitations_expiry_is_bounded
        CHECK (expires_at > created_at AND expires_at < created_at + interval '90 days'),
    CONSTRAINT invitations_used_together CHECK ((used_at IS NULL) = (used_by IS NULL))
);

-- The claim path looks up live invitations by hash. Partial, because used and
-- expired rows are kept for the audit trail and must not slow the lookup.
CREATE INDEX invitations_live_idx ON core.invitations (token_hash)
    WHERE used_at IS NULL AND revoked_at IS NULL;
CREATE INDEX invitations_by_org_idx ON core.invitations (org_id, created_at DESC);

ALTER TABLE core.invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY invitations_org_isolation ON core.invitations
    USING (org_id = core.current_org_id());

-- Open self-signup, when an organisation wants it.
--
-- Deliberately NOT a boolean. "Anyone may sign up" is almost never the intent;
-- "anyone with an @acme.com address that Google has verified" usually is, and a
-- checkbox cannot express the difference. An organisation with no row here does
-- not accept self-signup at all, which is the safe default and the one that
-- does not need to be chosen.
CREATE TABLE core.signup_rules (
    org_id uuid PRIMARY KEY REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- Empty means no domain restriction, which is only reachable by asking for
    -- it explicitly on the command line.
    allowed_domains text[] NOT NULL DEFAULT '{}',

    -- Groups every self-signed-up account joins.
    default_groups  text[] NOT NULL DEFAULT '{}',

    -- Whether the address must be proved before the account can sign in.
    -- On by default: an unverified self-signup is an account in somebody else's
    -- name, and the cost of getting this wrong is borne by the person whose
    -- address was used.
    require_verified_email boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE core.signup_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.signup_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY signup_rules_org_isolation ON core.signup_rules
    USING (org_id = core.current_org_id());

COMMENT ON TABLE core.invitations IS
    'Single-use, expiring invitations to create one account, optionally bound '
    'to an email address and carrying the groups the account will join.';
COMMENT ON TABLE core.signup_rules IS
    'Open self-signup, per organisation. No row means self-signup is refused.';
