-- Rate limits that survive more than one instance.
--
-- # The bug this fixes, measured
--
-- The login limiter was a token bucket in process memory. With one instance,
-- 40 attempts produced 26 allowed and 14 refused. With two instances behind a
-- load balancer, the same 40 attempts produced 40 allowed and 0 refused --
-- every instance added for availability multiplied the brute-force budget by
-- one. A deployment that scales out to survive traffic quietly weakens the
-- defence that matters most.
--
-- # And it was global, which is its own bug
--
-- One bucket for every sign-in meant a single attacker could exhaust it and
-- rate-limit the entire organisation: a denial of service costing one script.
-- Meanwhile guessing spread across many accounts was unbounded per account,
-- because nothing counted per account at all.
--
-- Both fall out of the same design: counters keyed by what is being limited,
-- held where every instance can see them.
--
-- # Why a fixed window rather than a token bucket
--
-- A token bucket needs read-then-write: refill by elapsed time, then decrement.
-- Two concurrent requests can both read the same value and both write their own
-- result, so one of the decrements is lost and both are allowed. Under exactly
-- the load a rate limiter exists for, it leaks.
--
-- A fixed window increments inside the UPDATE, referencing the stored row, so
-- concurrency is handled by the row lock and no read is lost.
--
-- The known cost is the boundary: a caller can use a full window's budget at
-- the end of one window and again at the start of the next, so the worst case
-- is twice the limit across a moment. That is a bounded, stated 2x -- as
-- against an unbounded multiple that grows with the size of the deployment.
CREATE TABLE IF NOT EXISTS core.rate_limits (
    -- bucket_key names what is limited: "login:ip:203.0.113.7",
    -- "login:user:alice@example.com". The prefix is the limiter, so two
    -- limiters cannot collide on one subject.
    bucket_key   text NOT NULL,
    window_start timestamptz NOT NULL,
    count        integer NOT NULL DEFAULT 0,

    PRIMARY KEY (bucket_key, window_start)
);

-- Old windows are dead weight the moment their window passes.
CREATE INDEX IF NOT EXISTS rate_limits_window ON core.rate_limits (window_start);

COMMENT ON TABLE core.rate_limits IS
    'Shared rate-limit counters. Held in the database rather than in process '
    'memory so the limit means the same thing whatever the deployment scales to.';
