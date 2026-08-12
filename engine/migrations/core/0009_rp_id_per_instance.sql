-- 0009_rp_id_per_instance.sql
--
-- The WebAuthn RP ID, as configuration rather than a constant, with its
-- irreversibility ENFORCED instead of documented.
--
-- ADR-002 called this "BLOCKED on the real domain" and treated it as a decision
-- the vendor makes once. That framing was wrong twice over:
--
--   * It is not ours to make. Every deployment sets its own, because their users
--     authenticate on their domain, not on signari.dev.
--   * "Never change this" written in a document is not a control. It is a hope.
--
-- What makes RP ID special is that the browser enforces it. A passkey is stored
-- inside the authenticator alongside the RP ID it was created for, and the
-- browser will not even OFFER a credential whose RP ID does not match the page's
-- origin. Change the value and every existing passkey silently disappears: no
-- error, no migration path, just users who suddenly have no passkey and no way
-- to get the old one back.
--
-- So the rule is enforced where it cannot be forgotten: once a single credential
-- exists for an instance, the database refuses to change that instance's RP ID.
-- Before the first credential it is freely editable, which is exactly the window
-- an operator needs to get it right.

SET search_path = core, public;

ALTER TABLE instances
    ADD COLUMN rp_id text,
    -- What the browser shows in the passkey prompt: "Create a passkey for X".
    ADD COLUMN rp_display_name text;

-- No scheme, no port, no path, no trailing dot. WebAuthn RP IDs are bare
-- domains, and every one of these mistakes produces a ceremony that fails in the
-- browser with a message that does not name the cause.
ALTER TABLE instances ADD CONSTRAINT instances_rp_id_is_a_bare_domain
    CHECK (rp_id IS NULL OR rp_id ~ '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$');

CREATE OR REPLACE FUNCTION core.refuse_rp_id_change() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    existing bigint;
BEGIN
    IF OLD.rp_id IS NOT DISTINCT FROM NEW.rp_id THEN
        RETURN NEW;
    END IF;

    -- Setting it for the first time is always allowed; there is nothing bound to
    -- it yet.
    IF OLD.rp_id IS NULL THEN
        RETURN NEW;
    END IF;

    SELECT count(*) INTO existing
    FROM core.webauthn_credentials c
    JOIN core.organizations o ON o.id = c.org_id
    WHERE o.instance_id = OLD.id;

    IF existing > 0 THEN
        RAISE EXCEPTION
            'refusing to change rp_id from % to %: % passkey(s) are bound to it and would be '
            'permanently unusable. Delete them deliberately first if that is really intended.',
            OLD.rp_id, NEW.rp_id, existing
            USING ERRCODE = 'raise_exception';
    END IF;

    RETURN NEW;
END
$$;

CREATE TRIGGER instances_rp_id_immutable
    BEFORE UPDATE ON instances
    FOR EACH ROW EXECUTE FUNCTION core.refuse_rp_id_change();

-- Development default. `localhost` is a valid RP ID and browsers treat it as a
-- secure context, so passkeys work over plain HTTP there and nowhere else --
-- which is the correct shape for a default nobody should ship.
UPDATE instances SET rp_id = 'localhost', rp_display_name = COALESCE(display_name, 'Signari')
WHERE rp_id IS NULL AND (issuer LIKE 'http://localhost%' OR issuer LIKE 'http://127.0.0.1%');
