SET search_path = core, public;

-- LDAP write operations: the two attributes a `person` entry MUST have.
--
-- RFC 4519 makes `cn` and `sn` MUST attributes of the `person` object class,
-- and every entry the LDAP shim returns has always declared itself
-- `top, person, organizationalPerson, inetOrgPerson`.
--
-- `sn` was never stored and never returned. So every entry this directory
-- published was schema-invalid against a class it declared -- which no client
-- complained about, because almost nothing validates a search result against a
-- schema it did not fetch. It was found the other way round: working out what an
-- Add request would have to accept, and noticing that the answer included an
-- attribute we had no column for.
--
-- Both are nullable. Rows that predate this migration have no surname, and the
-- read side derives one from the display name for those rather than publishing a
-- `person` with no `sn` -- see ldapd.surnameFrom, which is labelled as the guess
-- it is. A row written through the directory carries what the client actually
-- sent.
-- And `cn`, which had nowhere to go at all.
--
-- This table has never held a display name. The LDAP shim published
-- `cn: <username>` and `displayName: <username>`, and the OIDC `name` claim is
-- assembled elsewhere -- so an Add carrying `cn: Alice Okonkwo` had no column to
-- land in. Accepting it and dropping it is the failure this whole exercise is
-- against: the client writes a name, reads the entry back, and finds its own
-- username staring at it.
ALTER TABLE users
    ADD COLUMN display_name text,
    ADD COLUMN surname      text,
    ADD COLUMN given_name   text;

COMMENT ON COLUMN users.display_name IS
    'RFC 4519 cn. NULL falls back to the username, which is what this directory published before it could be written to.';
COMMENT ON COLUMN users.surname IS
    'RFC 4519 sn. Written through the LDAP directory; NULL for accounts created any other way, where the read side derives one from the display name.';
COMMENT ON COLUMN users.given_name IS
    'RFC 4519 givenName. Optional in the schema and optional here.';

-- Neither may be blank when present.
--
-- An empty string and a NULL would mean the same thing to every reader and
-- different things to every query, and `sn` is a MUST attribute: a row storing
-- '' would satisfy "has a surname" in SQL and produce an entry that violates its
-- own object class on the wire.
ALTER TABLE users
    ADD CONSTRAINT users_display_name_not_blank
    CHECK (display_name IS NULL OR length(btrim(display_name)) > 0),
    ADD CONSTRAINT users_surname_not_blank
    CHECK (surname IS NULL OR length(btrim(surname)) > 0),
    ADD CONSTRAINT users_given_name_not_blank
    CHECK (given_name IS NULL OR length(btrim(given_name)) > 0);
