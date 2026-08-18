-- The one-active-key constraint has to know about purpose.
--
-- 0074 added `purpose` to core.signing_keys so OpenID Federation Entity
-- Statement keys could live beside the protocol keys and inherit their rotation,
-- wrapping and retirement machinery.
--
-- It did not update this index, which was
--
--     UNIQUE (instance_id, algorithm) WHERE state = 'active'
--
-- and is exactly right for a table holding one kind of key. With two, an active
-- ES256 federation key collides with the active ES256 protocol key. The
-- collision is not a policy decision -- it is the index not having been told the
-- table now holds two independent key populations.
--
-- Found by running `signari federation enable` against an instance that already
-- had OIDC keys, which is every instance. Reading 0074 would not have found it;
-- the index is not mentioned there.
DROP INDEX IF EXISTS core.signing_keys_one_active;
CREATE UNIQUE INDEX signing_keys_one_active
    ON core.signing_keys (instance_id, purpose, algorithm)
    WHERE state = 'active';
