-- RFC 9396 Rich Authorization Requests.
--
-- `scope` is a list of bare strings, so a permission with structure -- move this
-- amount between these accounts, sign this document, issue this credential --
-- has to be encoded into one. Deployments end up inventing
-- `payment:500:GB123:GB456`, and every party has to agree how to split it.
--
-- `authorization_details` gives the permission a shape instead.
--
-- # Why types are registered rather than free-form
--
-- §5 requires the authorization server to REFUSE an object "of known type but
-- containing unknown fields", which is only possible if the server knows what
-- fields the type has. §10 says "The registration of authorization details types
-- with the AS is outside the scope of this specification" -- so this table is
-- our answer to a question the RFC deliberately leaves open.
--
-- It registers FIELDS, not value schemas. §2.2 says the allowable values "are
-- determined by the API being protected", which is not something this server can
-- check; a validator that pretended to would look stricter than it is.
CREATE TABLE core.authorization_detail_types (
    org_id      uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,

    -- The `type` value clients send. §2: "The value is unique for the described
    -- API in the context of the AS."
    type        text NOT NULL,

    -- Which of §2.2's common data fields this type uses, and which it requires.
    -- Required must be a subset of fields, enforced below rather than in code,
    -- because a registration that requires a field it does not permit can never
    -- be satisfied and should not be storable.
    fields      text[] NOT NULL DEFAULT '{}',
    required    text[] NOT NULL DEFAULT '{}',

    description text,
    created_at  timestamptz NOT NULL DEFAULT now(),

    PRIMARY KEY (org_id, type),

    CONSTRAINT authorization_detail_types_known_fields CHECK (
        fields <@ ARRAY['locations','actions','datatypes','identifier','privileges']
    ),
    CONSTRAINT authorization_detail_types_required_subset CHECK (required <@ fields)
);

-- Which types a client may ask for.
--
-- §10 lets a client declare `authorization_details_types` at registration. An
-- allow-list rather than "any registered type", for the same reason the group
-- release policy is one: a client that can request any permission the deployment
-- has ever defined is a client whose consent screen can say anything.
CREATE TABLE core.client_authorization_detail_types (
    client_id text NOT NULL REFERENCES core.clients(client_id) ON DELETE CASCADE,
    org_id    uuid NOT NULL REFERENCES core.organizations(id) ON DELETE CASCADE,
    type      text NOT NULL,
    PRIMARY KEY (client_id, type)
);

-- The details actually granted, carried with the authorization.
--
-- On the code and on the refresh family, because §7 requires the token response
-- to return "the authorization_details as granted by the resource owner and
-- assigned to the respective access token" -- which has to survive a refresh, or
-- the second token silently carries different permissions from the first.
ALTER TABLE core.authorization_codes ADD COLUMN authorization_details jsonb;
ALTER TABLE core.refresh_token_families ADD COLUMN authorization_details jsonb;

COMMENT ON TABLE core.authorization_detail_types IS
    'RFC 9396 §10 type registration. Declares which common data fields each authorization details type uses, so section 5 unknown-field rejection is possible.';
