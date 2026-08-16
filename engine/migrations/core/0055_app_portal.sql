-- What a user sees when they ask "what can I get into?"
--
-- Signari has had no answer to that question. A user knows an application
-- exists because somebody sent them a link, and when the link stops working
-- they open a support ticket. That is the single most common identity support
-- burden and it is entirely avoidable.
--
-- Access itself is NOT stored here. It is decided by the access policy at the
-- moment the portal is rendered, which is deliberately different from how the
-- other products do it: a static assignment table says "Alice may use Payroll"
-- and cannot say "from the office, on a managed device, during working hours".
-- Rendering the portal through the live policy means the list a user sees is
-- the list they can actually open, including conditions that change during the
-- day.

-- Where the portal sends someone.
--
-- initiate_login_uri is the standard OpenID Connect registration field for
-- exactly this: the URL a third party uses to start login AT THE APPLICATION.
-- Sending the user to our own authorize endpoint instead would skip the
-- application's own state, which is how a portal link lands people on a blank
-- dashboard rather than the page they wanted.
ALTER TABLE core.clients
    ADD COLUMN initiate_login_uri text,
    ADD COLUMN logo_uri text,
    -- Machine-to-machine clients have no user-facing surface, and listing them
    -- makes the portal a directory of internal services. Hidden by default for
    -- clients that cannot start a browser flow.
    ADD COLUMN portal_hidden boolean NOT NULL DEFAULT false;

-- Both must be https for the same reason every other URL here must be: a
-- portal tile is a link a user is invited to trust.
ALTER TABLE core.clients
    ADD CONSTRAINT clients_initiate_login_uri_https
        CHECK (initiate_login_uri IS NULL
               OR initiate_login_uri LIKE 'https://%'
               OR initiate_login_uri LIKE 'http://localhost%'
               OR initiate_login_uri LIKE 'http://127.0.0.1%'),
    ADD CONSTRAINT clients_logo_uri_https
        CHECK (logo_uri IS NULL OR logo_uri LIKE 'https://%');

COMMENT ON COLUMN core.clients.initiate_login_uri IS
    'Where the application portal sends a user. The OIDC registration field of '
    'the same name: login starts at the APPLICATION so its own state survives.';
COMMENT ON COLUMN core.clients.portal_hidden IS
    'Keep this client off the portal. Set for machine-to-machine clients and '
    'for applications whose existence should not be disclosed by a listing.';

-- Clients that cannot start a browser flow are hidden from the outset, so an
-- existing deployment does not suddenly publish its service accounts.
UPDATE core.clients
   SET portal_hidden = true
 WHERE NOT ('authorization_code' = ANY(grant_types));
