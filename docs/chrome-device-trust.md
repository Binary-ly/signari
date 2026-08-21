# Chrome Enterprise device trust

A managed Chrome installation can prove which device it is running on. The
browser signs a challenge with a key attested by Google, and Google's Verified
Access API turns the signed response into facts: which device, whether it is
managed by *this* customer, whether disk encryption and screen lock are on.

## It is a posture source, not a separate feature

Signari already had a device posture layer with two sources — a client
certificate and a header from a trusted proxy — and an access policy that speaks
`device_managed` and `device_compliant`. Chrome device trust is a **third source
of the same facts**.

```yaml
- name: payroll-from-managed-devices-only
  when: {client: payroll}
  require:
    device_managed: true
    device_compliant: true
  message: Payroll is only available from a managed, encrypted device.
```

That policy was written before Chrome device trust existed and needs no change.
Making it a source rather than a parallel concept means `signari policy test`
covers it, and there is one answer to "was this device trusted" rather than two
that can disagree.

Precedence: **certificate → Chrome → header**. A certificate and a Chrome
attestation are signatures; a header is an assertion by whatever was in the
network path.

## Three refusals worth stating

**Another customer's device is not our device.** Google will happily verify a
response from a device enrolled by a different Workspace customer. Without
checking the customer ID, "managed" means "managed by somebody", which is not a
security property.

**A software key proves a browser profile, not a device.** Google reports
`CHROME_BROWSER_HW_KEY` or `CHROME_BROWSER_OS_KEY`; only the first is held in
hardware. The device is reported unmanaged rather than refused — it is still a
signal, and a policy demanding managed devices will refuse it anyway.

**Silence is not compliance.** Posture signals arrive as strings —
`ENCRYPTED`, `UNSUPPORTED`, `UNKNOWN`. A device whose policy has not reached it
reports `UNKNOWN`, and treating that as satisfied is how an unencrypted laptop
passes a disk-encryption requirement.

## One bug worth recording

The first version tested the key trust level with
`strings.Contains(level, "HARDWARE")`. That reads correctly and **never fires**:
Google's value is `CHROME_BROWSER_HW_KEY`. Every device would have been reported
as a software key, so no device would ever have been trusted — a failure closed
rather than open, but a failure that would have made the feature useless and
looked like Chrome's fault.

It was caught because the test used Google's real enum values rather than
plausible-looking ones.

## What has not been verified

**No real Chrome Enterprise tenant.** The verification logic, the customer
check, the key trust level and the tri-state signal handling are all tested
against a fake Verified Access API. Nothing has been exchanged with Google.
That needs a Workspace tenant with Chrome Enterprise, and it is in
the open-decisions list rather than implied to be done.
