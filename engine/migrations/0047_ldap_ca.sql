-- An LDAP source's CA bundle.
--
-- Almost every directory worth syncing from is internal, and internal means a
-- private CA: an Active Directory domain controller's certificate is issued by
-- the organisation's own PKI, not by a public root. Without somewhere to put
-- that bundle the only ways to connect are the system roots (which will not
-- have it) or skipping verification (which turns a sync carrying every
-- employee's identity into a machine-in-the-middle's shopping list).
--
-- So: a column, and no InsecureSkipVerify anywhere.
ALTER TABLE core.directory_sources
    ADD COLUMN IF NOT EXISTS ldap_ca_pem text;

COMMENT ON COLUMN core.directory_sources.ldap_ca_pem IS
    'PEM roots used to verify the directory server. NULL uses the system roots.';
