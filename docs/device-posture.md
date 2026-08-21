# Device posture

Device trust as **a line in the policy file**, not a subsystem.

```yaml
policies:
  - name: finance-needs-a-managed-device
    when: {client: finance-app}
    require: {device_managed: true}
    message: Finance is only reachable from a company device.

  - name: admin-console-needs-a-compliant-one
    when: {client: admin-console}
    require: {device_compliant: true}
```


## Why a policy condition beats a subsystem

It diffs in a pull request. It is covered by the file's own tests, which run
before the file is allowed to load. Turning it on for one client is one line
rather than a console journey. And it composes with everything else already in
the language — groups, MFA, networks, impossible travel — instead of being a
parallel set of rules evaluated somewhere else.

The file's tests carry the interesting cases:

```
ok   an ordinary app is unaffected
ok   finance from a managed laptop
ok   finance from a personal machine
ok   the console from a managed but unhealthy device
ok   the console from a compliant device
ok   a compliance claim without management is not enough
```

Change a rule without updating its tests and the file **refuses to load**:

```
signari: this policy does not do what its tests say:
  finance from a personal machine: expected allow, got deny
```

## Two claims, kept apart

`device_managed` — the organisation issued this device.
`device_compliant` — and it is currently reported healthy.

Collapsing them would let a **stolen managed laptop** satisfy a rule written to
check its state. Compliance also implies management: an unmanaged device cannot
be reported compliant by anything worth believing, so the stricter condition
checks both.

## No agent

This project has said it will not build endpoint agents — a different product,
privileged software on every machine, and a bigger commitment than most
deployments realise. Posture is derived from evidence the request already
carries.

### Device certificate (strong)

```sh
SIGNARI_DEVICE_CA=/etc/signari/device-ca.pem
```

The device presents an mTLS certificate issued by the organisation's device
authority. The private key lives on the machine, usually in hardware, and cannot
be copied into a request by somebody who knows a header name.

A certificate establishes **managed**, never **compliant**. An MDM that revokes
certificates for unhealthy devices makes those equivalent; one that does not,
does not. The honest reading is managed-only.

A certificate that does not chain to the device authority is treated as *no
evidence*, not as an error — an unmanaged personal device is an ordinary request.

### Trusted proxy header (only as strong as the proxy)

```sh
SIGNARI_DEVICE_TRUSTED_PROXIES=10.0.0.0/8
SIGNARI_DEVICE_MANAGED_HEADER=X-Device-Managed
```

A posture header is a claim by whoever sent it. Accepting one from anywhere turns
device trust into "send this header" — **worse** than no device trust, because a
policy that reads as enforced stops being questioned.

So the address allow-list is mandatory. With no trusted proxies configured,
headers are ignored entirely whatever they say. A header from an untrusted source
is not an error either: it reports as *no evidence*, because answering
differently would confirm the header name means something.

`0.0.0.0/0` is refused at configuration: trusting the whole internet to assert
its own posture is the same as having none.

It is offered at all because many real deployments have an MDM-aware proxy and no
device PKI, and refusing them pushes them toward nothing.

### Which wins

Certificate over header, always. One is cryptographic; the other is an assertion
by a machine in the path.

## `false` is not `true`

`truthy` accepts `1`, `true`, `yes`, `managed`, `compliant` and nothing else.
Treating any non-empty value as true would make `X-Device-Managed: false` mean
managed — a bug that survives review because the header is present and the policy
passes.

## Evaluated only when asked

`UsesDevicePosture()` gates the whole thing, like the impossible-travel check
before it. A deployment whose policy never mentions a device never verifies a
chain or reads a header.

With nothing configured, `posture` is nil and a rule requiring a device is simply
never satisfied — visible, rather than silently permissive.

## The firewall signal (21 August 2026)

Found by sweeping the codebase for wire fields that are decoded and never read —
the same sweep that found LDAP's `typesOnly` and `timeLimit`.

`verifyResponse.DeviceSignal.OSFirewall` was parsed out of Google's Verified
Access response and left out of the compliance verdict, under a comment claiming
compliance meant *"the posture signals Google reports are all satisfied"*. It did
not: a managed device with disk encryption and a screen lock but its host
firewall switched off was reported **compliant**, by a rule whose own
documentation said it checked everything reported.

Either the code or the comment was wrong, and which one is not a question the
specification answers — it is a policy question about the fleet.

**Adding the signal unconditionally would have been the wrong fix**, and it is
the fix that looks obviously right. Disk encryption and screen lock are close to
universal on managed estates. The host firewall is not: plenty of managed macOS
and Linux fleets run with it off deliberately, behind a network their
administrators already control. Turning it on for everybody would have locked
those users out of their identity provider to enforce a policy nobody set here —
and the failure would have arrived as "logins stopped working after an upgrade",
with nothing in the response saying which signal caused it.

So it is opt-in, via `SIGNARI_CHROME_REQUIRE_FIREWALL=1`, with the default
preserving current behaviour. What was actually broken was not the policy but the
inability to express one: an operator who *did* require a host firewall had no
way to say so, and the next person to read the file could not tell whether the
omission was deliberate.

An absent `osFirewall` counts as **not** satisfied when the signal is required,
which is the rule the other signals already follow: a policy that has not reached
a device reports nothing, and reading silence as compliance is how a requirement
quietly stops applying to exactly the devices that are out of management.

```
CAUGHT   ignore the flag and never check the firewall (the state before this pass)
CAUGHT   always check the firewall (the tempting one-line fix — locks out fleets)
CAUGHT   treat an absent firewall signal as satisfied
```

The middle one is the reason this is three tests rather than one.
