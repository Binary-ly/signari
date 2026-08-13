-- 0015_per_client_issuer.sql
--
-- Per-client issuer override, so an OAuth migration becomes a DNS change.
--
-- # The problem this solves
--
-- Moving to a new identity provider normally means editing every downstream
-- application: new issuer, new client id, new secret, new discovery URL, new
-- JWKS. In an organisation with forty applications, several of them owned by
-- teams with their own release cycles, that is not a migration -- it is a
-- twelve-month programme, and it is the single biggest reason people stay where
-- they are.
--
-- Two features together remove it:
--
--   1. VERBATIM CLIENT IMPORT. `client create -client-id` already accepts an
--      arbitrary id, and secrets can be imported as-is, so an application's
--      existing credentials keep working.
--
--   2. ISSUER ALIASING (this migration). Tokens for a migrated client carry the
--      OLD issuer string, so the application's existing `iss` check passes and
--      its cached discovery document still matches.
--
-- Point the old issuer's hostname at us, and the applications never notice. They
-- are then migrated to the real issuer one at a time, on their own schedule,
-- with no deadline and no outage.
--
-- # Why this is dangerous, and what constrains it
--
-- An issuer claim is a security boundary: it is how a relying party knows which
-- authority minted a token. Issuing tokens under another authority's name is
-- exactly what a mix-up attack does.
--
-- So it is constrained three ways:
--   * The alias must be REGISTERED on the instance (instance_issuer_aliases).
--     A client cannot name any issuer it likes.
--   * It is per client, not global. One migrated application does not change
--     what anybody else receives.
--   * It carries a retirement date, because an alias that never expires is not a
--     migration aid, it is a permanent second identity for the deployment.

SET search_path = core, public;

ALTER TABLE clients
    ADD COLUMN issuer_alias text;

-- The alias must be one this instance actually claims. Enforced by trigger
-- rather than a foreign key because the check spans the client's organisation to
-- its instance, which a FK cannot express.
CREATE OR REPLACE FUNCTION core.check_client_issuer_alias() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ok boolean;
BEGIN
    IF NEW.issuer_alias IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM core.organizations o
        JOIN core.instance_issuer_aliases a ON a.instance_id = o.instance_id
        WHERE o.id = NEW.org_id AND a.issuer = NEW.issuer_alias
    ) INTO ok;

    IF NOT ok THEN
        RAISE EXCEPTION
            'issuer_alias % is not registered for this instance; register it in '
            'core.instance_issuer_aliases first. Minting tokens under an issuer '
            'this deployment does not claim is a mix-up attack.', NEW.issuer_alias
            USING ERRCODE = 'raise_exception';
    END IF;
    RETURN NEW;
END
$$;

CREATE TRIGGER clients_issuer_alias_registered
    BEFORE INSERT OR UPDATE OF issuer_alias, org_id ON clients
    FOR EACH ROW EXECUTE FUNCTION core.check_client_issuer_alias();

COMMENT ON COLUMN clients.issuer_alias IS
    'Cutover only: mint this client''s tokens under a registered legacy issuer so its existing configuration keeps working.';
