// Two FAPI 2.0 clients' ES256 keys: the private JWK sets the suite signs with, and the
// public ones the engine is given. Node's own crypto, so nothing is installed for it.
//
//   node fapikeys.mjs ../tls
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";

const [dir] = process.argv.slice(2);
for (const n of [1, 2]) {
  if (existsSync(`${dir}/fapi${n}.private.json`)) continue;
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const kid = randomBytes(8).toString("hex");
  const meta = { kid, alg: "ES256", use: "sig" };
  writeFileSync(`${dir}/fapi${n}.private.json`, JSON.stringify({ keys: [{ ...privateKey.export({ format: "jwk" }), ...meta }] }),
    { mode: 0o600 });
  writeFileSync(`${dir}/fapi${n}.public.json`, JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), ...meta }] }));
}
