-- Let an invitation be claimed before the account it creates exists.
--
-- 0057 asserted that used_at and used_by are set together:
--
--     CHECK ((used_at IS NULL) = (used_by IS NULL))
--
-- which contradicts the protocol in the same change. Claiming has to happen
-- FIRST -- a single UPDATE that both filters on `used_at IS NULL` and sets it,
-- so two people following the same forwarded link cannot both succeed. The user
-- does not exist at that moment; it is created afterwards, and used_by is
-- filled in then.
--
-- The constraint made every claim fail. Worth noting how it presented: the
-- endpoint reported "that invitation link is not valid", because the handler
-- treated any error from the claim as a refusal. A constraint violation and an
-- expired link are not the same thing and must not read the same, so the
-- handler now logs the difference.
ALTER TABLE core.invitations DROP CONSTRAINT IF EXISTS invitations_used_together;

-- What was actually meant: used_by is only ever set on an invitation that has
-- been claimed. The reverse is legitimate and transient.
ALTER TABLE core.invitations
    ADD CONSTRAINT invitations_user_implies_used
        CHECK (used_by IS NULL OR used_at IS NOT NULL);
