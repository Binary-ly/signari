-- signari:compatible-with-previous
--
-- 0182_persistent_sessions.sql
--
-- Whether an organisation offers "stay signed in on this device" (5.11).
--
-- The session cookie was a browser-session cookie, so closing the browser
-- signed the person out of everything, whatever the session's lifetime said.
-- When this is on, the sign-in page offers a checkbox, and a session signed in
-- with it ticked gets a cookie that lasts until the session's own deadline.
-- The session ends exactly as before, at its lifetime, its idle limit or a
-- sign-out; only the browser forgetting it on restart changes. Off by default,
-- because a shared computer is where that matters.
--
-- Compatible with the release before: a column with a default, which it never
-- reads.

ALTER TABLE core.organizations ADD COLUMN persistent_sessions boolean NOT NULL DEFAULT false;

COMMENT ON COLUMN core.organizations.persistent_sessions IS
    'Whether the sign-in page offers "stay signed in on this device". `signari instance session-lifetime -persistent`.';
