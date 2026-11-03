// The OID4VP verifier plan's issuer key: the suite plays a wallet holding a credential
// signed with it, so it is given the private JWK, and the engine is told to believe the
// public one. Node's own crypto, so nothing is installed for it.
//
//   node vpkeys.mjs ../tls
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";

const [dir] = process.argv.slice(2);
if (!existsSync(`${dir}/vp-issuer.private.json`)) {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const meta = { kid: randomBytes(8).toString("hex"), alg: "ES256", use: "sig" };
  writeFileSync(`${dir}/vp-issuer.private.json`, JSON.stringify({ ...privateKey.export({ format: "jwk" }), ...meta }),
    { mode: 0o600 });
  writeFileSync(`${dir}/vp-issuer.public.json`, JSON.stringify({ keys: [{ ...publicKey.export({ format: "jwk" }), ...meta }] }));
}
