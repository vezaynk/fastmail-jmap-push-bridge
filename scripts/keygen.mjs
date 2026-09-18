#!/usr/bin/env node
/**
 * Generate UA Web Push keys for this bridge.
 * Prints public parts + the PUSH_UA_PRIVATE_JWK secret value.
 * Does not write secrets to disk.
 */
import { webcrypto } from "node:crypto";

const crypto = webcrypto;

function b64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return Buffer.from(s, "binary").toString("base64url");
}

function publicJwkToUncompressed(jwk) {
  const x = Buffer.from(jwk.x, "base64url");
  const y = Buffer.from(jwk.y, "base64url");
  return Buffer.concat([Buffer.from([0x04]), x, y]);
}

const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
  "deriveBits",
]);
const privateJwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
const publicJwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
const clean = {
  kty: "EC",
  crv: "P-256",
  d: privateJwk.d,
  x: privateJwk.x ?? publicJwk.x,
  y: privateJwk.y ?? publicJwk.y,
};
const auth = b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
const p256dh = b64urlEncode(publicJwkToUncompressed(clean));
const privateJwkJson = JSON.stringify(clean);

console.log(JSON.stringify({ p256dh, auth, PUSH_UA_PRIVATE_JWK: privateJwkJson }, null, 2));
console.log("\n# Set secrets:");
console.log(`echo '${privateJwkJson}' | wrangler secret put PUSH_UA_PRIVATE_JWK`);
console.log(`echo -n '${p256dh}' | wrangler secret put PUSH_P256DH`);
console.log(`echo -n '${auth}' | wrangler secret put PUSH_AUTH`);
