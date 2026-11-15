-- 0301_public_clients_authenticate_by_none.sql
--
-- A client's token_endpoint_auth_method said what the column's default said, not how it
-- authenticates. A public client holds no secret and authenticates by nothing, PKCE its
-- proof, yet five of the ways to make one (the command line's client create, the importer,
-- config-as-code, the Admin API's create and dynamic registration) stored client_secret_post,
-- so the Admin API, the console and Terraform reported every such client as sending a
-- secret. Dynamic registration also told a confidential registrant client_secret_basic and
-- stored client_secret_post. Each now writes what it means, and the rows they wrote are put
-- right. Nothing a client can do changes: a public client is never authenticated by this
-- column, and the confidential path accepts a secret sent either way.
-- Not compatible with the previous release, by the rule for a migration that writes rows.

UPDATE core.clients SET token_endpoint_auth_method = 'none'
 WHERE client_type = 'public' AND token_endpoint_auth_method <> 'none';

UPDATE core.clients SET token_endpoint_auth_method = 'client_secret_basic'
 WHERE dynamically_registered AND client_type = 'confidential'
   AND token_endpoint_auth_method = 'client_secret_post';
