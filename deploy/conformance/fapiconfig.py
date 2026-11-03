#!/usr/bin/env python3
"""The FAPI 2.0 plan's configuration: config.json's server, the two clients setup.sh made,
their private keys from ../tls, and userinfo as the protected resource.

    python3 fapiconfig.py /elsewhere/fapi.json
    CONFIG=/elsewhere/fapi.json ./run.sh fapi2
    python3 fapiconfig.py --message-signing /elsewhere/fapims.json
    CONFIG=/elsewhere/fapims.json ./run.sh fapi2-ms
    python3 fapiconfig.py --vci /elsewhere/vci.json
    CONFIG=/elsewhere/vci.json ./run.sh vci

Written outside this directory, because it holds the clients' private keys.
"""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
signing = "--message-signing" in sys.argv[1:]
prefix = "conformance-fapims" if signing else "conformance-fapi"
cfg = json.load(open(os.path.join(here, "config.json")))
cfg["description"] = "signari engine -- FAPI 2.0" + (" Message Signing" if signing else "")
for slot, n in (("client", 1), ("client2", 2)):
    with open(os.path.join(here, "..", "tls", f"fapi{n}.private.json")) as keys:
        cfg[slot] = {"client_id": f"{prefix}-{n}", "scope": "openid email", "jwks": json.load(keys)}
cfg.pop("client_secret_post", None)
cfg["resource"] = {"resourceUrl": "https://signari-engine:8080/oauth2/userinfo"}
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
out = [a for a in sys.argv[1:] if not a.startswith("--")][0]
with open(out, "w") as f:
    json.dump(cfg, f, indent=1)
os.chmod(out, 0o600)
print(f"written to {out}")
