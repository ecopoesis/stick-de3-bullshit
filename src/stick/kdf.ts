// Stick-DE3 DMX cipher — per-session AES-256 key derivation (KDF).
//
// TypeScript port of tools/derive-dmx-key.mjs (which remains the canonical
// reference). The .mjs version is kept untouched so diagnostic tools that
// import it (verify-kdf.mjs, decrypt-dmx.mjs, etc.) keep working.
//
// Math summary (verified end-to-end against a real session):
//
//   curve = NIST P-256 / prime256v1
//   d     = random scalar mod n              (ephemeral private, 32B)
//   our   = d · G                            (our public key, sent in 0x0F)
//   Q     = stick's response pubkey          (received in 0x0F reply)
//   S     = decompress(STATIC_POINT_33B)     (hardcoded in HM binary)
//
//   AES-256 key = LE( X(d · S)  XOR  X(d · Q) )
//
// Endianness: every 256-bit coord on the wire is LITTLE-endian limbs;
// node's `crypto` works in big-endian (SEC1), so we byte-reverse at every
// boundary. The installed AES key is the LE form of the XOR.

import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';

export const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  a: 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffcn,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  Gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  Gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n,
} as const;

// 33-byte SEC1-compressed static point. Stored verbatim at HardwareManager
// file offset 0x7b0490 (vmaddr 0x1007b0490), prefix 0x03 (odd Y).
export const STATIC_POINT_COMPRESSED = Buffer.from(
  '0328081290396d063e5114526ed978b926558f6ba1c96ad2facf76fffb3ffea0fe',
  'hex',
);

const rev = (b: Buffer): Buffer => Buffer.from(b).reverse();
const pad32 = (b: Buffer): Buffer =>
  b.length >= 32 ? b.subarray(b.length - 32)
                 : Buffer.concat([Buffer.alloc(32 - b.length), b]);

function modpow(base: bigint, exp: bigint, mod: bigint): bigint {
  let r = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) r = (r * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return r;
}

/** SEC1-decompress a 33-byte compressed point to 65-byte uncompressed. */
export function decompressPoint(compressed33: Buffer): Buffer {
  const { p, a, b } = P256;
  const prefix = compressed33[0];
  const x = BigInt('0x' + compressed33.subarray(1, 33).toString('hex'));
  const rhs = ((((x * x) % p) * x) % p + ((a * x) % p) + b) % p;
  let y = modpow(rhs, (p + 1n) / 4n, p); // p ≡ 3 (mod 4)
  if ((y * y) % p !== rhs) throw new Error('static point X is not on P-256');
  if ((y & 1n) !== BigInt(prefix & 1)) y = p - y;
  const hex = (v: bigint) => v.toString(16).padStart(64, '0');
  return Buffer.from('04' + hex(x) + hex(y), 'hex');
}

/** Uncompressed SEC1 point (65B, 0x04‖X_be‖Y_be) → 64B little-endian wire. */
export function pointToWire(uncompressed65: Buffer): Buffer {
  const xbe = uncompressed65.subarray(1, 33);
  const ybe = uncompressed65.subarray(33, 65);
  return Buffer.concat([rev(xbe), rev(ybe)]);
}

/** 64B little-endian wire point → uncompressed SEC1 (65B) for node crypto. */
export function wireToPoint(wire64: Buffer): Buffer {
  const xbe = rev(wire64.subarray(0, 32));
  const ybe = rev(wire64.subarray(32, 64));
  return Buffer.concat([Buffer.from([0x04]), xbe, ybe]);
}

/** Create the ephemeral P-256 keypair (steps 1-2 of the KDF). */
export function makeEphemeral(): crypto.ECDH {
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.generateKeys();
  return ecdh;
}

/** Derive the per-session AES-256 key.
 *   key = LE( X(d·S) XOR X(d·Q) ) */
export function deriveDmxKey(ecdh: crypto.ECDH, stickPub65: Buffer): Buffer {
  const S = decompressPoint(STATIC_POINT_COMPRESSED);
  const x1 = pad32(ecdh.computeSecret(S));
  const x2 = pad32(ecdh.computeSecret(stickPub65));
  const xorBE = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) xorBE[i] = x1[i] ^ x2[i];
  return rev(xorBE);
}
