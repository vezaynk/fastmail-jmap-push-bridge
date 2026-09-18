/**
 * Web Push decryption (UA role) per RFC 8291 §3.4 + RFC 8188 aes128gcm (single record).
 *
 * Secrets:
 *   PUSH_UA_PRIVATE_JWK — JSON string of EC P-256 JWK including "d" (private), "x", "y"
 *   PUSH_P256DH         — uncompressed public key (65 bytes starting 0x04), base64url
 *   PUSH_AUTH           — 16-byte authentication secret, base64url
 */

import { b64urlDecode, b64urlEncode, concatBytes } from "./base64url";

const te = new TextEncoder();

export type EcPrivateJwk = JsonWebKey & {
  kty: "EC";
  crv: "P-256";
  d: string;
  x: string;
  y: string;
};

function asBufferSource(data: Uint8Array): BufferSource {
  // Copy into a fresh ArrayBuffer to satisfy strict BufferSource typing under workers-types.
  const copy = new Uint8Array(data.byteLength);
  copy.set(data);
  return copy;
}

export function parseUaPrivateJwk(raw: string): EcPrivateJwk {
  const jwk = JSON.parse(raw) as JsonWebKey;
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.d || !jwk.x || !jwk.y) {
    throw new Error("PUSH_UA_PRIVATE_JWK must be an EC P-256 JWK with d, x, y");
  }
  return jwk as EcPrivateJwk;
}

/** Uncompressed P-256 point (0x04 || x || y) → JWK public fields. */
export function uncompressedToPublicJwk(point: Uint8Array): JsonWebKey {
  if (point.length !== 65 || point[0] !== 0x04) {
    throw new Error("Invalid uncompressed P-256 public key (want 65 bytes, leading 0x04)");
  }
  return {
    kty: "EC",
    crv: "P-256",
    x: b64urlEncode(point.slice(1, 33)),
    y: b64urlEncode(point.slice(33, 65)),
  };
}

/** JWK public (x,y) → uncompressed point. */
export function publicJwkToUncompressed(jwk: { x?: string; y?: string }): Uint8Array {
  if (!jwk.x || !jwk.y) throw new Error("JWK missing x/y");
  return concatBytes(new Uint8Array([0x04]), b64urlDecode(jwk.x), b64urlDecode(jwk.y));
}

async function hmacSha256(key: Uint8Array, data: Uint8Array): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return crypto.subtle.sign("HMAC", cryptoKey, asBufferSource(data));
}

/**
 * Decrypt an aes128gcm Web Push body (UA role).
 * Returns UTF-8 plaintext bytes (typically JSON).
 */
export async function decryptWebPush(
  body: ArrayBuffer | Uint8Array,
  uaPrivateJwk: EcPrivateJwk,
  authSecret: Uint8Array,
): Promise<Uint8Array> {
  const bytes = body instanceof Uint8Array ? body : new Uint8Array(body);
  if (bytes.length < 21) throw new Error("aes128gcm body too short");

  const salt = bytes.slice(0, 16);
  const idlen = bytes[20]!;
  if (bytes.length < 21 + idlen + 16) throw new Error("aes128gcm body truncated");
  const asPublic = bytes.slice(21, 21 + idlen);
  const ciphertext = bytes.slice(21 + idlen);

  if (asPublic.length !== 65 || asPublic[0] !== 0x04) {
    throw new Error("aes128gcm keyid must be uncompressed P-256 public key");
  }

  const uaPrivateKey = await crypto.subtle.importKey(
    "jwk",
    { ...uaPrivateJwk, key_ops: ["deriveBits"], ext: true },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  );

  const asPublicKey = await crypto.subtle.importKey(
    "jwk",
    { ...uncompressedToPublicJwk(asPublic), key_ops: [], ext: true },
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );

  const ecdhSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: asPublicKey },
    uaPrivateKey,
    256,
  );

  const uaPublic = publicJwkToUncompressed(uaPrivateJwk);

  // HKDF-Extract(salt=auth_secret, IKM=ecdh_secret)
  const prkKey = new Uint8Array(await hmacSha256(authSecret, new Uint8Array(ecdhSecret)));
  // HKDF-Expand → IKM
  const keyInfo = concatBytes(
    te.encode("WebPush: info"),
    new Uint8Array([0x00]),
    uaPublic,
    asPublic,
    new Uint8Array([0x01]),
  );
  const ikm = new Uint8Array(await hmacSha256(prkKey, keyInfo));

  // RFC 8188 HKDF
  const prk = new Uint8Array(await hmacSha256(salt, ikm));

  const cekInfo = concatBytes(te.encode("Content-Encoding: aes128gcm"), new Uint8Array([0x00, 0x01]));
  const cek = new Uint8Array(await hmacSha256(prk, cekInfo)).slice(0, 16);

  const nonceInfo = concatBytes(te.encode("Content-Encoding: nonce"), new Uint8Array([0x00, 0x01]));
  const nonce = new Uint8Array(await hmacSha256(prk, nonceInfo)).slice(0, 12);

  const aesKey = await crypto.subtle.importKey(
    "raw",
    asBufferSource(cek),
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  let plainWithPad: Uint8Array;
  try {
    plainWithPad = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: asBufferSource(nonce), tagLength: 128 },
        aesKey,
        asBufferSource(ciphertext),
      ),
    );
  } catch {
    throw new Error("AES-GCM decryption failed (bad key or ciphertext)");
  }

  // RFC 8188: content || delimiter(0x02) || zero padding
  let end = plainWithPad.length;
  while (end > 0 && plainWithPad[end - 1] === 0x00) end--;
  if (end === 0 || plainWithPad[end - 1] !== 0x02) {
    throw new Error("Invalid aes128gcm padding delimiter (expected 0x02)");
  }
  return plainWithPad.slice(0, end - 1);
}

export async function decryptWebPushToString(
  body: ArrayBuffer | Uint8Array,
  uaPrivateJwk: EcPrivateJwk,
  authSecret: Uint8Array,
): Promise<string> {
  const pt = await decryptWebPush(body, uaPrivateJwk, authSecret);
  return new TextDecoder().decode(pt);
}

/** Generate UA ECDH keypair + 16-byte auth secret. */
export async function generatePushKeys(): Promise<{
  privateJwk: EcPrivateJwk;
  p256dh: string;
  auth: string;
  privateJwkJson: string;
}> {
  const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
    "deriveBits",
  ]);
  const privateJwk = (await crypto.subtle.exportKey("jwk", pair.privateKey)) as EcPrivateJwk;
  const publicJwk = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  if (!privateJwk.x) privateJwk.x = publicJwk.x!;
  if (!privateJwk.y) privateJwk.y = publicJwk.y!;
  privateJwk.kty = "EC";
  privateJwk.crv = "P-256";

  const authBytes = crypto.getRandomValues(new Uint8Array(16));
  const p256dh = b64urlEncode(publicJwkToUncompressed({ x: privateJwk.x, y: privateJwk.y }));
  const auth = b64urlEncode(authBytes);

  const clean: EcPrivateJwk = {
    kty: "EC",
    crv: "P-256",
    d: privateJwk.d!,
    x: privateJwk.x!,
    y: privateJwk.y!,
  };

  return {
    privateJwk: clean,
    p256dh,
    auth,
    privateJwkJson: JSON.stringify(clean),
  };
}

export { b64urlDecode, b64urlEncode };
