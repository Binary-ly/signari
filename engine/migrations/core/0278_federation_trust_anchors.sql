-- signari:compatible-with-previous
-- 0278_federation_trust_anchors.sql
--
-- OpenID Federation Automatic Registration (§12.1), an RP using this OP with no prior
-- step because a federation vouches for it. Nothing does that here until an operator
-- writes down whose word to take: with no rows, nobody is admitted. Each anchor names
-- the organisation the RPs it vouches for land in, since a client has to be somebody's.

CREATE TABLE core.federation_trust_anchors (
    instance_id          uuid        NOT NULL REFERENCES core.instances(id) ON DELETE CASCADE,
    entity_id            text        NOT NULL,
    org_id               uuid        NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    -- Its Federation Entity Keys, as an operator was given them. Fetched instead, the
    -- anchor would be whoever answers at that address.
    jwks                 jsonb       NOT NULL,
    -- Trust Mark types an RP must hold besides, each valid under §7.3.
    required_trust_marks text[]      NOT NULL DEFAULT '{}',
    created_at           timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (instance_id, entity_id),
    CONSTRAINT federation_trust_anchors_https CHECK (entity_id LIKE 'https://%')
);

CREATE INDEX federation_trust_anchors_org ON core.federation_trust_anchors (org_id);

ALTER TABLE core.federation_trust_anchors ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.federation_trust_anchors FORCE ROW LEVEL SECURITY;
CREATE POLICY federation_trust_anchors_org_isolation ON core.federation_trust_anchors
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());

GRANT SELECT ON core.federation_trust_anchors TO signari_maintenance;

CREATE TRIGGER federation_trust_anchors_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.federation_trust_anchors
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();

-- Which anchor admitted a client, and when what it was told stops holding. Both NULL on
-- every client an operator made.
ALTER TABLE core.clients ADD COLUMN federation_anchor text;
ALTER TABLE core.clients ADD COLUMN federation_expires_at timestamptz;

-- §12.1.1.1: "A Request Object MUST only be used once". The key alone stands in for a
-- secret here, so a captured object would otherwise be good until its exp.
CREATE TABLE core.request_object_replay (
    client_id  text        NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    jti        text        NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (client_id, jti)
);

CREATE INDEX request_object_replay_expiry ON core.request_object_replay (expires_at);

ALTER TABLE core.request_object_replay ENABLE ROW LEVEL SECURITY;
ALTER TABLE core.request_object_replay FORCE ROW LEVEL SECURITY;
CREATE POLICY request_object_replay_engine ON core.request_object_replay
    USING (core.is_engine()) WITH CHECK (core.is_engine());

GRANT SELECT ON core.request_object_replay TO signari_maintenance;

CREATE TRIGGER request_object_replay_cli_bumps_version
    AFTER INSERT OR UPDATE OR DELETE ON core.request_object_replay
    FOR EACH STATEMENT EXECUTE FUNCTION core.bump_config_version_for_cli();
