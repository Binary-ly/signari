-- signari:compatible-with-previous
--
-- 0295_admin_token_attributes.sql
--
-- Narrowing an admin token to named user attributes (ASVS 5.0.0 V8.2.3, field-level
-- access): such a token reads, sets and clears only those attributes' values, releases only
-- those to applications through claim mappers, and is refused what reaches every attribute at
-- once (a person's whole export, a configuration file, an upstream's attribute map). Until
-- now `users:read` read every value a person held, personal ones unsealed, so a help desk's
-- lookup token read what a payroll integration's needed. NULL is every attribute, as for
-- client_ids and group_ids (0120), and an empty array is none. Compatible with the previous
-- release, which ignores the column: a narrowed token is then unnarrowed there.

ALTER TABLE core.admin_tokens
    ADD COLUMN attribute_names text[];

COMMENT ON COLUMN core.admin_tokens.attribute_names IS
    'User attributes this token may read, set or release, by name. NULL means every attribute '
    'in its organisation; an empty array means none. The two are deliberately different.';
