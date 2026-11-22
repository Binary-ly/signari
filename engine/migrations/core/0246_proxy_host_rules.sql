-- signari:compatible-with-previous
-- 0246_proxy_host_rules.sql
--
-- What forward authentication does with one path of a protected application (8.26), where the
-- host alone does not say enough. On the host's row because they are the host's, read with it on
-- every request, and replaced together: their order is what they mean. Empty is a host as every
-- host has been, and an older binary ignores the column, which leaves it protecting every path.

ALTER TABLE core.proxy_hosts ADD COLUMN rules jsonb NOT NULL DEFAULT '[]';
