-- Retirement, the last step of the rotation machine that was documented and
-- never built.
--
-- `internal/keys` has always described `next -> active -> passive -> removed`,
-- and `MinPassiveBeforeRetire` has been declared since the machine was written.
-- Nothing read it. Passive keys stayed in the JWKS forever, so the key set grew
-- with every rotation and no key ever left.
--
-- 'retired' is a fourth state rather than a DELETE. A deleted row loses the
-- record that the key existed at all, which is the one thing an operator needs
-- when a relying party turns up months later complaining about an unknown `kid`
-- -- "we retired it on this date" is an answer; a missing row is a mystery. The
-- key material stays wrapped in the row and simply stops being published.
ALTER TABLE core.signing_keys DROP CONSTRAINT signing_keys_state_check;
ALTER TABLE core.signing_keys ADD CONSTRAINT signing_keys_state_check
    CHECK (state = ANY (ARRAY['next', 'active', 'passive', 'retired']));

-- `retire_after` records the deadline that was computed at demotion time, so the
-- decision is auditable after the fact rather than recomputed from whatever the
-- configuration happens to say later. It has existed as an unused column since
-- the table was created; this is what it was for.
COMMENT ON COLUMN core.signing_keys.retire_after IS
    'Earliest instant this key may leave the JWKS. Set at demotion from the '
    'passive dwell in force at that moment; NULL means it has not been demoted.';
