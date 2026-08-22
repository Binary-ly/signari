SET search_path = core, public;

-- Which assertion issuers a given client may present assertions from.
--
-- # The gap this closes
--
-- Two gates already exist for the RFC 7523 jwt-bearer grant: the provider must be
-- opted in (`identity_providers.allow_jwt_bearer`), and the client must be
-- registered for the grant (`clients.grant_types`). Both are necessary and
-- together they are not sufficient, because they do not relate the two.
--
-- In an organisation that trusts GitHub Actions AND a Kubernetes cluster, any
-- client holding the grant can spend an assertion from either. A client that
-- exists to let one CI pipeline reach one API can present a pod's service-account
-- token instead. Nothing crosses a tenant boundary, and it is still authority
-- nobody granted.
--
-- The most deployed implementation of this grant has the same list
-- (`getJWTAuthorizationGrantAllowedIdentityProviders`), and reading their code is
-- how this gap was found in ours.
--
-- # An empty list permits nothing
--
-- Not "everything", which is the tempting reading for a column that defaults to
-- empty. This engine already has that rule written down, for SSF event sources:
-- "An empty list allows nothing. A source configured with no events is a source
-- somebody has not finished configuring, and reading that as 'everything' is how
-- a half-made configuration becomes a live grant."
--
-- The same applies here, and more sharply: the default is what every existing
-- client gets, so a permissive default would leave the gap open for exactly the
-- clients nobody has revisited.
--
-- Slugs rather than identifiers, because a slug is what the operator types at
-- `idp assertions -slug` and reads in `idp list`, and it is unique per
-- organisation -- which is the only scope in which this list is ever consulted.
ALTER TABLE clients
    ADD COLUMN jwt_bearer_providers text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN clients.jwt_bearer_providers IS
    'Slugs of the identity providers whose assertions this client may exchange '
    'via urn:ietf:params:oauth:grant-type:jwt-bearer. Empty permits none.';
