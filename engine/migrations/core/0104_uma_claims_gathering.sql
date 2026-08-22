SET search_path = core, public;

-- UMA 2.0 interactive claims gathering and pushed claims.
--
-- Kantara Recommendation, 7 January 2018: sections 3.3.1 (claim_token),
-- 3.3.2 and 3.3.3 (the claims interaction endpoint), and 3.3.6 (need_info,
-- request_denied, request_submitted).
--
-- # What changes about the grant
--
-- Until now the requesting party WAS the client: this server answered from
-- policy alone and had no way to learn who was behind the request. That made the
-- UMA grant a decorated client-credentials exchange. The whole point of UMA is
-- that a resource owner can write policy about a PERSON they have never
-- provisioned, and that only works once the request can carry one.
--
-- So a ticket can now be bound to a requesting party, and everything below
-- exists to get one there safely.

-- Section 3.3.2's claims redirection URIs.
--
--   "Claims redirection URIs are different from the redirection URIs defined in
--   [RFC6749] in that they are intended for the exclusive use of requesting
--   parties and not resource owners. Therefore, authorization servers MUST NOT
--   redirect requesting parties to pre-registered redirection URIs defined in
--   [RFC6749] unless such URIs are also pre-registered specifically as claims
--   redirection URIs."
--
-- A separate column rather than reusing redirect_uris, because that MUST NOT is
-- the entire reason the parameter has its own name. The two lists overlap in
-- practice and the specification still insists they be declared separately: a
-- resource owner's redirect endpoint and a requesting party's are different
-- trust boundaries even when they are the same host.
ALTER TABLE clients ADD COLUMN claims_redirect_uris text[];

-- https only, and no fragment. Section 3.3.2: "The URI MUST be absolute, MAY
-- contain an application/x-www-form-urlencoded-formatted query parameter
-- component that MUST be retained when adding additional parameters, and MUST
-- NOT contain a fragment component."
--
-- The https requirement is ours: the redirect carries a permission ticket, which
-- is a bearer credential, and a plaintext hop hands it to the network.
--
-- Via a function because PostgreSQL forbids a subquery in a CHECK, and every
-- way of asking "does every element of this array satisfy P" needs one. The
-- alternative is validating only in Go, which leaves a direct INSERT -- a
-- migration, a repair script, an import -- free to write a plaintext URI that
-- the engine will then happily redirect a permission ticket to.
CREATE OR REPLACE FUNCTION core.uris_are_https_without_fragment(uris text[])
RETURNS boolean LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    -- coalesce on BOTH sides. NULL in, no rows out of unnest, bool_and returns
    -- NULL, and a CHECK treats NULL as satisfied -- which happens to be the
    -- answer we want here and would be the wrong one for a constraint whose
    -- absent case should fail. Written explicitly so the next such function is
    -- not copied from this one by accident.
    SELECT coalesce(bool_and(u LIKE 'https://%' AND u NOT LIKE '%#%'), true)
      FROM unnest(coalesce(uris, ARRAY[]::text[])) u
$$;

ALTER TABLE clients ADD CONSTRAINT clients_claims_redirect_uris_are_https
    CHECK (core.uris_are_https_without_fragment(claims_redirect_uris));

COMMENT ON COLUMN clients.claims_redirect_uris IS
    'UMA 2.0 section 3.3.2. Deliberately NOT the same list as redirect_uris: the specification forbids redirecting a requesting party to an RFC 6749 redirect URI unless it is also registered here.';

-- Section 3.3.6's request_submitted, and whether this deployment offers it.
--
-- Section 3.3.4 makes it conditional on capability, not on preference: the
-- authorization server may answer request_submitted only "if [it] has a way to
-- notify the resource owner about the ... resource request and seek an added
-- policy covering it". Absent a row this is off, and a refusal stays
-- request_denied -- which is FINAL, and telling a client to poll forever for a
-- decision nobody will ever be asked to make is worse than refusing outright.
CREATE TABLE uma_settings (
    org_id uuid PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,

    -- Whether a denied request from an identified requesting party is recorded
    -- for a resource owner to act on.
    owner_intervention boolean NOT NULL DEFAULT false,

    -- Section 3.3.6's `interval`: "The minimum amount of time in seconds that
    -- the client SHOULD wait between polling requests to the token endpoint."
    --
    -- Bounded at both ends. Below five seconds a polling client is a load
    -- generator against the token endpoint; above an hour the client has almost
    -- certainly given up, and a value that guarantees nobody is listening is a
    -- worse answer than a short one.
    poll_interval_seconds int NOT NULL DEFAULT 30
        CHECK (poll_interval_seconds BETWEEN 5 AND 3600),

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE uma_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE uma_settings FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_settings_org_isolation ON uma_settings
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
GRANT SELECT ON uma_settings TO signari_maintenance;

COMMENT ON TABLE uma_settings IS
    'UMA 2.0 per-organisation settings. Absent means resource-owner intervention is not offered, so a refusal is final (request_denied) rather than submitted.';

-- A request a resource owner has been asked to decide, section 3.3.6.
CREATE TABLE uma_pending_requests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,

    -- The resource server whose permission ticket started this.
    resource_server text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,
    -- The client asking on the requesting party's behalf. Usually the same as
    -- the resource server and not necessarily so, which is why both are kept.
    client_id text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- Who is asking. NOT NULL: a request nobody can be named for is one a
    -- resource owner cannot possibly decide, and section 3.3.4 reaches
    -- request_submitted only after claims have been gathered.
    requesting_party uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    -- What was asked for, verbatim from the ticket.
    permissions jsonb NOT NULL,

    state text NOT NULL DEFAULT 'pending'
        CHECK (state IN ('pending', 'approved', 'denied')),
    decided_at timestamptz,
    decided_by uuid REFERENCES users(id) ON DELETE SET NULL,
    -- What was granted, when it was approved: the relation an operator chose.
    -- Recorded so "why does this person have access" has an answer that names
    -- the decision rather than only its effect.
    granted_relation text,

    CONSTRAINT uma_pending_decision_is_dated
        CHECK ((state = 'pending') = (decided_at IS NULL)),

    created_at timestamptz NOT NULL DEFAULT now(),
    -- Bounded, and swept by the janitor. A pending request is a standing offer
    -- to grant access; one that nobody decided for a month should lapse rather
    -- than sit there waiting to be approved by somebody who has forgotten the
    -- context.
    expires_at timestamptz NOT NULL
);

-- One live request per (client, requesting party, resource server). A client
-- polling every thirty seconds must not enqueue a new decision each time.
CREATE UNIQUE INDEX uma_pending_requests_one_per_asker
    ON uma_pending_requests (org_id, client_id, requesting_party, resource_server)
    WHERE state = 'pending';

CREATE INDEX uma_pending_requests_expiry ON uma_pending_requests (expires_at);

ALTER TABLE uma_pending_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE uma_pending_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_pending_requests_org_isolation ON uma_pending_requests
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
GRANT SELECT ON uma_pending_requests TO signari_maintenance;

COMMENT ON TABLE uma_pending_requests IS
    'UMA 2.0 section 3.3.6 request_submitted: a refused request recorded for a resource owner to decide. Approval grants a relation in the authorization model, so the next poll passes policy on its own.';

-- A ticket can now carry who is asking, and which pending decision it polls.
ALTER TABLE uma_permission_tickets
    ADD COLUMN requesting_party uuid REFERENCES users(id) ON DELETE CASCADE,
    ADD COLUMN pending_request_id uuid REFERENCES uma_pending_requests(id) ON DELETE CASCADE,
    -- The client the ticket was minted FOR, once claims gathering has bound one.
    -- Until then a ticket is presentable by any client in the organisation,
    -- which is what section 3.2 intends: the resource server hands it to a
    -- stranger. After claims gathering it is not -- the requesting party proved
    -- their identity to one client, and letting a second client present that
    -- ticket would be handing it their session.
    ADD COLUMN bound_client text REFERENCES clients(client_id) ON DELETE CASCADE;

-- A requesting party is only ever bound by the claims interaction endpoint or by
-- a pushed claim token, and either way there is a client in front of it. A row
-- with one and not the other would be a ticket carrying an identity that no
-- client is accountable for.
ALTER TABLE uma_permission_tickets
    ADD CONSTRAINT uma_ticket_identity_has_a_client
    CHECK ((requesting_party IS NULL) = (bound_client IS NULL));

COMMENT ON COLUMN uma_permission_tickets.requesting_party IS
    'The person on whose behalf the client is asking, established by the claims interaction endpoint (section 3.3.2) or by a pushed claim token (section 3.3.1). NULL means the requesting party is the client itself.';

-- Section 3.3.2's interaction, as a record rather than as a redirect.
--
-- The endpoint is a GET carrying a ticket, and section 5.1 requires CSRF
-- protection AND that "a malicious client cannot obtain authorization without
-- the awareness and involvement of the requesting party". A GET that redeems the
-- ticket and redirects is exactly the attack that names: an <img> tag in an
-- email spends the victim's identity with no involvement at all.
--
-- So the GET renders a confirmation and this row is what the confirmation refers
-- to; the POST does the work. The row exists so the POST cannot be forged into
-- carrying a different redirect URI or a different ticket than the one the
-- person was shown.
CREATE TABLE uma_claims_interactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    client_id text NOT NULL REFERENCES clients(client_id) ON DELETE CASCADE,

    -- SHA-256 of the interaction handle put in the confirmation form. Never the
    -- handle: it is a bearer value for the duration of the page.
    handle_hash bytea NOT NULL UNIQUE CHECK (length(handle_hash) = 32),

    -- The ticket this interaction is about, and where to send the person back.
    ticket_hash bytea NOT NULL CHECK (length(ticket_hash) = 32),
    claims_redirect_uri text NOT NULL,
    -- Section 3.3.3: state "MUST be present if and only if the client provided
    -- it". An empty string and a NULL are therefore different, and the column is
    -- nullable so they stay so.
    state text,

    -- Whose browser this was. The POST must come from the same person the GET
    -- was rendered for.
    requesting_party uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,

    consumed_at timestamptz,
    expires_at  timestamptz NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX uma_claims_interactions_expiry ON uma_claims_interactions (expires_at);

ALTER TABLE uma_claims_interactions ENABLE ROW LEVEL SECURITY;
ALTER TABLE uma_claims_interactions FORCE ROW LEVEL SECURITY;
CREATE POLICY uma_claims_interactions_org_isolation ON uma_claims_interactions
    USING (core.is_engine() OR org_id = core.current_org_id())
    WITH CHECK (core.is_engine() OR org_id = core.current_org_id());
GRANT SELECT ON uma_claims_interactions TO signari_maintenance;

COMMENT ON TABLE uma_claims_interactions IS
    'One visit to the UMA claims interaction endpoint, held between the confirmation page and its submission so the submission cannot carry a different ticket or redirect URI than the one shown.';
