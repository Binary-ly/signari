# A sign-in from a new device

When somebody signs in to an account from a device none of its recent sessions
came from, the person is told: by mail, and by text where a number is
verified, in their own language.

> Your account was just signed in to from Firefox on Windows, which has not
> signed in to it in the last 90 days.

The mail says what to do if it was not them: change the password, and sign out
everywhere from the sessions page. It is a notice, not a gate. The sign-in goes
ahead either way.

## What counts as new

A device is a browser on a system, read from the User-Agent: "Safari on iOS",
"Chrome on Windows". Versions are left out, or every browser update would be a
new device, and so is the address, or every train journey would be. A sign-in is
from a new device when none of the person's sessions of the last 90 days came
from the same one, counted before its own session is written.

These are not told:

- a person's first sign-in in that time, which has nothing to differ from;
- a sign-in on a device the person ticked "remember this device" on;
- a browser that sends no User-Agent, which names no device.

Every way in passes the same check (the sign-in form, a passkey, an emailed
code, a provider, Kerberos), and the notice is queued in the sign-in's own
transaction, so a sign-in that does not complete tells nobody.

## Turning it off

```sh
signari instance new-device-notice -org <uuid> -notice off
```

On by default. An organisation whose people sign in from many shared machines
may find one mail per browser too many. Until October 2026 nothing told a person
about a sign-in from somewhere new; the session list showed it only to somebody
who went looking.
