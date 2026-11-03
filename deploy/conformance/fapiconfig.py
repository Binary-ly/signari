#!/usr/bin/env python3
"""The FAPI 2.0 plan's configuration: config.json's server, the two clients setup.sh made,
their private keys from ../tls, and userinfo as the protected resource.

    python3 fapiconfig.py /elsewhere/fapi.json
    CONFIG=/elsewhere/fapi.json ./run.sh fapi2

Written outside this directory, because it holds the clients' private keys.
"""
import json
import os
import sys

here = os.path.dirname(os.path.abspath(__file__))
cfg = json.load(open(os.path.join(here, "config.json")))
cfg["description"] = "signari engine -- FAPI 2.0"
for slot, n in (("client", 1), ("client2", 2)):
    with open(os.path.join(here, "..", "tls", f"fapi{n}.private.json")) as keys:
        cfg[slot] = {"client_id": f"conformance-fapi-{n}", "scope": "openid email", "jwks": json.load(keys)}
cfg.pop("client_secret_post", None)
cfg["resource"] = {"resourceUrl": "https://signari-engine:8080/oauth2/userinfo"}
out = sys.argv[1]
with open(out, "w") as f:
    json.dump(cfg, f, indent=1)
os.chmod(out, 0o600)
print(f"written to {out}")
