# Chrome Enterprise device trust

## Introduction

Acme may want payroll reached only from laptops it manages. A managed Chrome
installation can prove which device it is running on. The browser signs a
challenge with a key attested by Google. Google's Verified Access API then turns
the signed response into facts. They say which device it is, and whether it is
managed by *this* customer. They also say whether disk encryption and screen lock
are on.

Signari reads those facts as one more source of [device posture](device-posture.md),
so an access policy can require a managed, compliant device.

It is configured with the `SIGNARI_CHROME_*` environment variables, listed in
[configuration](configuration.md#chrome-enterprise-device-trust). It is off until
`SIGNARI_CHROME_CREDENTIALS` is set.

## It is a posture source, not a separate feature

Signari already had a device posture layer with two sources: a client
certificate, and a header from a trusted proxy. It also had an
[access policy](policy.md) that speaks `device_managed` and `device_compliant`.
Chrome device trust is a **third source of the same facts**.

This rule admits only managed, compliant devices to the payroll application:

```yaml
- name: payroll-from-managed-devices-only
  when: {client: payroll}
  require:
    device_managed: true
    device_compliant: true
  message: Payroll is only available from a managed, encrypted device.
```

That policy was written before Chrome device trust existed, and needs no change.
Making Chrome a source, rather than a parallel concept, means `signari policy test`
covers it. There is one answer to "was this device trusted", rather than two
that can disagree.

Precedence: **certificate → Chrome → header**. A certificate and a Chrome
attestation are signatures. A header is an assertion by whatever was in the
network path.

## Three refusals worth stating

**Another customer's device is not your device.** Google will happily verify a
response from a device enrolled by a different Workspace customer. Without
checking the customer ID, "managed" means "managed by somebody", which is not a
security property.

**A software key proves a browser profile, not a device.** Google reports
`CHROME_BROWSER_HW_KEY` or `CHROME_BROWSER_OS_KEY`, and only the first is held in
hardware. The device is reported unmanaged rather than refused. It is still a
signal, and a policy demanding managed devices will refuse it anyway.

**Silence is not compliance.** Posture signals arrive as strings, such as
`ENCRYPTED`, `UNSUPPORTED` and `UNKNOWN`. A device whose policy has not reached it
reports `UNKNOWN`. Treating that as satisfied is how an unencrypted laptop passes
a disk-encryption requirement.

## One bug worth recording

The first version tested the key trust level with
`strings.Contains(level, "HARDWARE")`. That reads correctly and **never fires**,
because Google's value is `CHROME_BROWSER_HW_KEY`.

Every device would have been reported as a software key, so no device would ever
have been trusted. That is a failure closed rather than open. But it would have
made the feature useless, and looked like Chrome's fault.

It was caught because the test used Google's real enum values, rather than
plausible-looking ones.

## What has not been verified

**No real Chrome Enterprise account has been used.** Everything is tested against
a fake Verified Access API. That covers the verification logic, the customer
check, the key trust level and the tri-state signal handling. Nothing has been
exchanged with Google.

That needs a Google Workspace account with Chrome Enterprise. It is in the
open-decisions list, rather than implied to be done.
