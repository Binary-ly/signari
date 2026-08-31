-- Narrowing an admin token to named objects.
--
-- # The gap this closes
--
-- An admin token carries scopes and an organisation. Inside that organisation a
-- `clients:write` token could change EVERY client — so a CI job that deploys one
-- application needed a credential able to disable the payroll system, and a
-- support desk token able to edit one team's group could edit every group.
--
-- Least privilege was therefore available at two granularities, tenant and
-- capability, and not at the one integrations actually need.
--
-- # NULL means every object, and that is the compatible default
--
-- An existing token has NULL here and is unchanged. The restriction is opt-in,
-- because making it mandatory would break every token already issued and be
-- worked around by whoever is holding the pager — the same reasoning that keeps
-- `If-Match` optional.
--
-- # An empty array is NOT "everything"
--
-- It is "nothing", and the distinction is the whole point. `'{}'` reading as
-- unrestricted is how a narrowing feature becomes a widening one: somebody
-- clears the list intending to revoke access and grants all of it instead. NULL
-- and empty must mean opposite things, and the check below refuses the
-- ambiguous middle by requiring an explicit NULL for "all".

ALTER TABLE core.admin_tokens
    ADD COLUMN client_ids text[],
    ADD COLUMN group_ids  uuid[];

COMMENT ON COLUMN core.admin_tokens.client_ids IS
    'Clients this token may act on. NULL means every client in its organisation; '
    'an empty array means none. The two are deliberately different.';

COMMENT ON COLUMN core.admin_tokens.group_ids IS
    'Groups this token may act on. NULL means every group in its organisation; '
    'an empty array means none.';
