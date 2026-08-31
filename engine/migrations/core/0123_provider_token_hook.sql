-- Let the token hook actually be registered.
--
-- # What was wrong
--
-- 0109 created `core.providers` with `CHECK (hook IN ('authorize'))`, which was
-- right at the time: `authorize` was the only hook. 0117 then added
-- `providers.allowed_claims` to bound what a TOKEN hook may contribute, and
-- `internal/provider` gained `HookTokenIssue`, and `flow.go` gained a call to
-- `ConsultTokenProvider` on the token path. The CHECK was never widened.
--
-- So every piece existed and the capability was unreachable:
--
--   `signari provider add -hook token_issue`  refused by this constraint
--   core.providers.allowed_claims             could never apply to any row
--   ConsultTokenProvider                      called on every token request,
--                                             found no provider, returned
--
-- Nothing errored. The hook simply never fired, which reads identically to "no
-- operator has configured one".
--
-- # Why the list is not open
--
-- The temptation is to drop the constraint so the next hook does not need a
-- migration. That would trade this failure for a worse one: a typo in `-hook`
-- would be stored, listed by `provider list`, and consulted by nothing -- the
-- same silence, arrived at from the other direction and with no way to tell it
-- from a hook that is simply never reached.
--
-- The constraint is the schema agreeing with `provider.allHooks`, and
-- `TestEverySupportedHookIsAcceptedBySchema` now fails the build when the two
-- disagree, so widening it stays a deliberate step that cannot be forgotten
-- again.

ALTER TABLE core.providers DROP CONSTRAINT providers_hook_check;

ALTER TABLE core.providers
    ADD CONSTRAINT providers_hook_check
    CHECK (hook IN ('authorize', 'token_issue'));

COMMENT ON COLUMN core.providers.hook IS
    'Which decision point consults this provider. Must match a Hook in internal/provider; the constraint and provider.allHooks are held together by TestEverySupportedHookIsAcceptedBySchema.';
