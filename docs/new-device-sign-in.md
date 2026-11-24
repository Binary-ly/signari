# A sign-in from a new device

## Introduction

A person whose password someone else has learned may not know until it is used.
A sign-in from a device they have never used is often the first sign.

When somebody signs in to an account from a device none of its recent sessions
came from, Signari tells the person. It tells them by mail, and by text message
where a number is verified, in their own language. It is a notice, not a gate:
the sign-in goes ahead either way.

The notice is on by default. You can turn it off for an organisation with
`signari instance new-device-notice`.

## What the notice says

The mail reads like this:

```text
Your account was just signed in to from Firefox on Windows, which has not
signed in to it in the last 90 days.
```

The mail also says what to do if it was not them: change the password, and sign
out everywhere from the sessions page.

## What counts as new

A "device" here is a browser on a system, read from the `User-Agent`, the name a
browser sends with each request. "Safari on iOS" and "Chrome on Windows" are
devices.

Versions are left out, or every browser update would be a new device. The
network address is left out too, or every train journey would be a new device.

A sign-in is from a new device when none of the person's sessions of the last 90
days came from the same one. That is counted before the sign-in's own session is
written.

These sign-ins send no notice:

- a person's first sign-in in that time, which has nothing to differ from;
- a sign-in on a device the person ticked "remember this device" on;
- a browser that sends no `User-Agent`, which names no device.

Every way in passes the same check: the sign-in form, a passkey, an emailed
code, a provider and Kerberos. The notice is queued in the sign-in's own
transaction, so a sign-in that does not complete tells nobody.

## Turning it off

To turn the notice off for an organisation:

```sh
signari instance new-device-notice -org <uuid> -notice off
```

The notice is on by default. An organisation whose people sign in from many
shared machines may find one mail per browser too many.

Until October 2026, nothing told a person about a sign-in from somewhere new.
The session list showed it only to somebody who went looking.
