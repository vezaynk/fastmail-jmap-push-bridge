/**
 * RFC 8291 §5 / Appendix A — decrypt the published aes128gcm example as the UA.
 *
 * Run: npm test
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  b64urlDecode,
  b64urlEncode,
  decryptWebPushToString,
  publicJwkToUncompressed,
  type EcPrivateJwk,
} from "../src/webpush.ts";

/** Collapse whitespace from RFC base64url examples. */
function b64(s: string): string {
  return s.replace(/\s+/g, "");
}

test("RFC 8291 §5 example decrypts to watermelon plaintext", async () => {
  // Body from §5 (base64url, line-wrapped)
  const bodyB64 = b64(`
    DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
    mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
    pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN
  `);
  const body = b64urlDecode(bodyB64);

  // Receiver (UA) keys from §5
  const uaPrivateRaw = b64("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94");
  const uaPublicRaw = b64(`
    BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcx
    aOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4
  `);
  const authSecret = b64urlDecode(b64("BTBZMqHH6r4Tts7J_aSIgg"));

  const uaPub = b64urlDecode(uaPublicRaw);
  assert.equal(uaPub.length, 65);
  assert.equal(uaPub[0], 0x04);

  const uaPrivateJwk: EcPrivateJwk = {
    kty: "EC",
    crv: "P-256",
    d: uaPrivateRaw,
    x: b64urlEncode(uaPub.slice(1, 33)),
    y: b64urlEncode(uaPub.slice(33, 65)),
  };

  // Sanity: round-trip uncompressed form
  const round = publicJwkToUncompressed(uaPrivateJwk);
  assert.deepEqual(round, uaPub);

  const plaintext = await decryptWebPushToString(body, uaPrivateJwk, authSecret);
  assert.equal(plaintext, "When I grow up, I want to be a watermelon");
});

test("header idlen is 65 and keyid starts with 0x04", () => {
  const bodyB64 = b64(`
    DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27ml
    mlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPT
    pK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN
  `);
  const body = b64urlDecode(bodyB64);
  assert.equal(body[20], 65);
  assert.equal(body[21], 0x04);
  // rs = 4096 = 0x00001000
  assert.equal(body[16], 0x00);
  assert.equal(body[17], 0x00);
  assert.equal(body[18], 0x10);
  assert.equal(body[19], 0x00);
});
