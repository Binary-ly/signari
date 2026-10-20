-- signari:compatible-with-previous
--
-- 0166_client_minimum_acr.sql
--
-- The weakest authentication a client accepts (4.02). '1' accepts a password
-- alone, which is what every client accepted before; '2' requires
-- multi-factor, whatever the client's own request asks for. A relying party
-- could ask with acr_values, and nothing let the operator require it of an
-- application that does not ask, or that a user could reach with the
-- parameter removed.
--
-- Compatible with the release before, which ignores the column. During a
-- rolling upgrade a floor holds only on the nodes that read it, so it is set
-- once every node runs this release.
ALTER TABLE core.clients ADD COLUMN minimum_acr text NOT NULL DEFAULT '1'
    CHECK (minimum_acr IN ('1', '2'));

COMMENT ON COLUMN core.clients.minimum_acr IS
    'The weakest authentication this client accepts: 1 a single factor, 2 '
    'multi-factor. Enforced at authorization, at a device or backchannel '
    'approval, and at every refresh. Set with `signari client set-acr`.';
