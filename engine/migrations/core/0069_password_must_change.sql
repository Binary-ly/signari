
ALTER TABLE core.password_credentials
    ADD COLUMN must_change        boolean     NOT NULL DEFAULT false,
    -- Shown to the person, so "you must change your password" is never a demand
    -- without a reason. An unexplained demand is indistinguishable from phishing.
    ADD COLUMN must_change_reason text,
    ADD COLUMN last_breach_check  timestamptz;

CREATE INDEX password_credentials_must_change_idx
    ON core.password_credentials (org_id) WHERE must_change;

COMMENT ON COLUMN core.password_credentials.must_change IS
    'Sign-in succeeds but routes to a password change before a session exists.';
