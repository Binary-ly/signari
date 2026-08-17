ALTER TABLE core.clients
    ADD COLUMN allow_hybrid boolean NOT NULL DEFAULT false,
    -- When the exemption should end. Not enforced by the engine -- an identity
    -- provider that starts refusing logins on a date nobody remembered setting
    -- is worse than the thing it was protecting against -- but reported by
    -- `signari client list`, so it is a question somebody is asked rather than a
    -- setting that quietly becomes permanent.
    ADD COLUMN hybrid_review_by date;

COMMENT ON COLUMN core.clients.allow_hybrid IS
    'Permit response_type=code id_token for this client. For migration only: '
    'the access token is never issued in the front channel regardless.';
COMMENT ON COLUMN core.clients.hybrid_review_by IS
    'When this exemption should be revisited. Reported, not enforced.';
