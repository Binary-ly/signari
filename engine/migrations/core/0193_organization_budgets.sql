-- signari:compatible-with-previous
--
-- 0193_organization_budgets.sql
--
-- Each organisation's own budget (6.10): how many tokens its clients may be
-- issued, and how many sign-ins its pages may take, a minute. Counted per
-- organisation in core.rate_limits, so one tenant's batch job or sign-in rush
-- spends its own budget and not the deployment's: before, the only limit on
-- sign-in was one bucket in each process that every tenant shared.
--
-- NULL is the deployment's default (store.DefaultTokenBudget,
-- store.DefaultSignInBudget). Set by a deployment-wide caller only, since a
-- tenant that set its own would have no budget.
--
-- Compatible with the release before, which never reads them.

ALTER TABLE core.organizations ADD COLUMN token_budget_per_minute integer
    CONSTRAINT organizations_token_budget_check CHECK (token_budget_per_minute BETWEEN 1 AND 1000000);
ALTER TABLE core.organizations ADD COLUMN signin_budget_per_minute integer
    CONSTRAINT organizations_signin_budget_check CHECK (signin_budget_per_minute BETWEEN 1 AND 1000000);

COMMENT ON COLUMN core.organizations.token_budget_per_minute IS
    'Tokens this organisation''s clients may be issued a minute; NULL for the deployment''s default.';
COMMENT ON COLUMN core.organizations.signin_budget_per_minute IS
    'Sign-ins this organisation''s pages may take a minute; NULL for the deployment''s default.';
