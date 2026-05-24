// Wire-protocol constants + low-level helpers for the Stick-DE3 control
// channel (TCP/2431) and the encrypted DMX stream (UDP/2431).
//
// Ported verbatim from tools/send_dmx.mjs (which is now frozen as the
// reference implementation). All offsets / magic / opcodes here have been
// reverse-engineered from the 2024-03-21 ESA2 HardwareManager binary; see
// the [[stick-cipher-is-stream-not-aes]] memory note for the full RE trail.

import { Buffer } from 'node:buffer';

export const TCP_PORT = 2431;
export const UDP_DST_PORT = 2431;
export const UDP_SRC_PORT = 2430;

export const MAGIC = Buffer.from('Stick_3A');
export const LSAG = Buffer.from('LSAG_ALL');

// 16-byte fixed plaintext header that every DMX frame starts with. Confirmed
// constant across ≥2 independent sessions. Recovered from decrypted frames.
export const P0 = Buffer.from('5b4e99da9685ad976c432b0a7ff9ffcc', 'hex');

// HMAC-SHA256 key for the 0x48 TCP-auth handshake.
//   = "#h.6xcKsGD{y}-z" (15 bytes), runtime-extracted from HardwareManager
//     and verified against a captured 0x48 message.
export const AUTH_KEY = Buffer.from('23682e3678634b7347447b797d2d7a', 'hex');

// The Stick's static 0x0F pubkey. Constant across every observed session
// (it's the "Q" the device claims as ephemeral but never actually rotates
// in practice). Used as a fallback if the live 0x0F reply can't be parsed.
// 64-byte little-endian wire form.
export const Q_FALLBACK = Buffer.from(
  '87ef58c2660c272b54a74bbc94cb8518108e370b7eed78456bd8d120c6b9ac0a' +
  'd791e4ce698aea761679f4b92a3ecf2acd12bf9bc308ce0ba8cb96630871105e',
  'hex',
);

/** A monotonic 4-byte LE counter shared between TCP messages and UDP frame
 *  fieldA. The Stick rejects out-of-order tokens. */
export class Token {
  private n: number;
  constructor(start = 0x80) { this.n = start; }
  next(): Buffer {
    const b = Buffer.alloc(8);
    b.writeUInt32LE(this.n++, 0);
    return b;
  }
  /** Current value without advancing. */
  peek(): number { return this.n; }
}

/** Build a TCP/2431 message: magic(8) ‖ opcode(2 LE) ‖ ...body parts. */
export function msg(magic: Buffer, opcode: number, ...parts: Buffer[]): Buffer {
  const op = Buffer.alloc(2);
  op.writeUInt16LE(opcode, 0);
  return Buffer.concat([magic, op, ...parts]);
}

/** Find a Stick_3A / LSAG_ALL message of `opcode` and at least `minLen`
 *  bytes inside the accumulating receive buffer. Returns the slice or null. */
export function findMsg(rxBuf: Buffer, opcode: number, minLen: number): Buffer | null {
  for (let o = 0; o + 10 <= rxBuf.length; o++) {
    const head = rxBuf.subarray(o, o + 8);
    if (!head.equals(MAGIC) && !head.equals(LSAG)) continue;
    if (rxBuf.readUInt16LE(o + 8) !== opcode) continue;
    if (rxBuf.length < o + minLen) continue;
    return rxBuf.subarray(o, o + minLen);
  }
  return null;
}

/** Poll a predicate every 20ms until it returns non-null or `timeoutMs`
 *  elapses. Returns the value or null on timeout. */
export function waitFor<T>(
  predicate: () => T | null,
  timeoutMs: number,
): Promise<T | null> {
  return new Promise((resolve) => {
    const deadline = Date.now() + timeoutMs;
    const tick = () => {
      const r = predicate();
      if (r != null) return resolve(r);
      if (Date.now() > deadline) return resolve(null);
      setTimeout(tick, 20);
    };
    tick();
  });
}

export const sleep = (ms: number): Promise<void> =>
  new Promise((r) => setTimeout(r, ms));
