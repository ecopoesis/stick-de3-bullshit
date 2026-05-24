// Encrypted 576-byte DMX frame builder.
//
// Layout (verified empirically 2026-05-23):
//
//   32-byte clear header
//   +0x00 (8B)  magic = "Stick_3A"
//   +0x08 (2B)  opcode 0x0019
//   +0x0a (8B)  fieldA — the shared session message counter (Token)
//   +0x12 (2B)  port — 0 for universe A; B unknown
//   +0x14 (2B)  channel count, always 512
//   +0x16 (1B)  constant 100
//   +0x17 (1B)  frame seq counter (per-frame, modulo 256)
//   +0x18 (8B)  random nonce
//
//   544-byte AES-256-CBC ciphertext
//     IV = fieldA(8) ‖ nonce(8)
//     plaintext = [P0(16)][zeros(16)][channels(512)]   ← off-by-16 fix
//                                                       (was [P0][channels][trailer])

import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';
import { MAGIC, P0 } from './protocol.js';

export interface FrameOpts {
  /** AES-256 session key (32B) from KDF */
  key: Buffer;
  /** 512 DMX channel values (0-255 each) */
  channels: Uint8Array;
  /** universe port id (0 = A; B not yet known) */
  port: number;
  /** 8-byte fieldA from the session Token counter */
  fieldA: Buffer;
  /** per-frame sequence counter (low byte) */
  seq: number;
}

/** Build one 576-byte encrypted DMX frame. */
export function buildFrame(opts: FrameOpts): Buffer {
  if (opts.channels.length !== 512) {
    throw new Error(`channels must be 512 bytes, got ${opts.channels.length}`);
  }
  if (opts.key.length !== 32) {
    throw new Error(`key must be 32 bytes (AES-256), got ${opts.key.length}`);
  }
  if (opts.fieldA.length !== 8) {
    throw new Error(`fieldA must be 8 bytes, got ${opts.fieldA.length}`);
  }

  const nonce = crypto.randomBytes(8);
  const iv = Buffer.concat([opts.fieldA, nonce]); // 16-byte CBC IV

  // [P0(16)][zeros(16)][channels(512)] = 544
  const plain = Buffer.concat([P0, Buffer.alloc(16), Buffer.from(opts.channels)]);

  const c = crypto.createCipheriv('aes-256-cbc', opts.key, iv);
  c.setAutoPadding(false);
  const body = Buffer.concat([c.update(plain), c.final()]); // 544

  const hdr = Buffer.alloc(32);
  MAGIC.copy(hdr, 0);
  hdr.writeUInt16LE(0x0019, 8);
  opts.fieldA.copy(hdr, 0x0a);
  hdr.writeUInt16LE(opts.port, 0x12);
  hdr.writeUInt16LE(512, 0x14);
  hdr[0x16] = 100;
  hdr[0x17] = opts.seq & 0xff;
  nonce.copy(hdr, 0x18);

  return Buffer.concat([hdr, body]); // 576
}
