#!/usr/bin/env python3
"""The FAPI 2.0 plan's configuration: config.json's server, the two clients setup.sh made,
their private keys from ../tls, and userinfo as the protected resource.

    python3 fapiconfig.py /elsewhere/fapi.json
    CONFIG=/elsewhere/fapi.json ./run.sh fapi2
    python3 fapiconfig.py --message-signing /elsewhere/fapims.json
    CONFIG=/elsewhere/fapims.json ./run.sh fapi2-ms
    python3 fapiconfig.py --vci /elsewhere/vci.json
    CONFIG=/elsewhere/vci.json ./run.sh vci
    python3 fapiconfig.py --mtls /elsewhere/fapitls.json
    CONFIG=/elsewhere/fapitls.json ./run.sh fapi2-mtls
    python3 fapiconfig.py --mtls-ca /elsewhere/fapica.json
    CONFIG=/elsewhere/fapica.json ./run.sh fapi2-mtls-ca
    python3 fapiconfig.py --vp /elsewhere/vp.json
    CONFIG=/elsewhere/vp.json ./run.sh vp          (and vp-plain)

Written outside this directory, because it holds the clients' private keys.
"""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
signing = "--message-signing" in sys.argv[1:]
issued = "--mtls-ca" in sys.argv[1:]
mtls = "--mtls" in sys.argv[1:] or issued
prefix = ("conformance-fapims" if signing else "conformance-fapica" if issued
          else "conformance-fapitls" if mtls else "conformance-fapi")
cfg = json.load(open(os.path.join(here, "config.json")))
cfg["description"] = "signari engine -- FAPI 2.0" + (" Message Signing" if signing else "")
for slot, n in (("client", 1), ("client2", 2)):
    with open(os.path.join(here, "..", "tls", f"fapi{n}.private.json")) as keys:
        cfg[slot] = {"client_id": f"{prefix}-{n}", "scope": "openid email", "jwks": json.load(keys)}
cfg.pop("client_secret_post", None)
cfg["resource"] = {"resourceUrl": "https://signari-engine:8080/oauth2/userinfo"}
if mtls:
    # The certificate and key each mutual-TLS client holds, which the suite presents:
    # self-signed, or issued by the conformance CA under --mtls-ca.
    stem = "fapica" if issued else "fapitls"
    for tls, n in (("mtls", 1), ("mtls2", 2)):
        with open(os.path.join(here, "..", "tls", f"{stem}{n}.crt")) as crt, \
                open(os.path.join(here, "..", "tls", f"{stem}{n}.key")) as key:
            cfg[tls] = {"cert": crt.read(), "key": key.read()}
if "--vci" in sys.argv[1:]:
    # The same clients as wallets, and this server as the credential issuer and its
    # authorization server; the plan reads neither a scope nor a resource.
    issuer = "https://signari-engine:8080"
    cfg["description"] = "signari engine -- OID4VCI issuer"
    cfg["vci"] = {"credential_issuer_url": issuer, "authorization_server": issuer,
                  "credential_configuration_id": "IdentityCredential"}
    for slot in ("client", "client2"):
        cfg[slot].pop("scope", None)
    cfg.pop("resource")
if "--vp" in sys.argv[1:]:
    # The OID4VP verifier plans, where the suite is the wallet: the key its credentials
    # are signed with, this server's host as the x509_san_dns client, the conformance CA
    # its request objects are checked against, and the suite's own evidence page caught
    # by its browser, as its CI does, so the positive modules need no screenshot.
    tls = os.path.join(here, "..", "tls")
    with open(os.path.join(tls, "vp-issuer.private.json")) as k, open(os.path.join(tls, "ca.crt")) as ca:
        evidence = "https://*/test/a/*/verification-evidence"
        cfg = {"alias": "signari-vp", "description": "signari engine -- OID4VP verifier",
               "client": {"client_id": "signari-engine", "request_object_trust_anchor_pem": ca.read()},
               "credential": {"signing_jwk": json.load(k)},
               "browser": [{"match": evidence, "tasks": [{"task": "Capture verification evidence", "match": evidence,
                            "commands": [["wait", "xpath", "//*", 10, ".*Deferred verification evidence.*",
                                          "update-image-placeholder"]]}]}]}
out = [a for a in sys.argv[1:] if not a.startswith("--")][0]
with open(out, "w") as f:
    json.dump(cfg, f, indent=1)
os.chmod(out, 0o600)
print(f"written to {out}")
