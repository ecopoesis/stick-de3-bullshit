// Try decrypting a captured 576-byte DMX frame using the hardcoded 33-byte
// secret discovered by Ghidra static RE.
//
// Background:
//   Ghidra found a deobfuscator (cipher vtable's vt[7], at FUN_100180E90 +
//   FUN_100180D40 — byte-identical compiler dupes). It reads 33 obfuscated
//   bytes at 0x1007B0490 and XORs them with the mask 0x51..0x71 to produce a
//   33-byte hardcoded secret. We decoded that secret offline:
//
//     hex: 527a5b46c56f3a5e670b4f0e338727d9
//          4737ec0fc4af0dba93a51d93965191d0
//          8f
//
//   It MIGHT be: 16-byte AES-128 key + 16-byte IV + 1-byte flag (33 total),
//   used directly by the cipher without any per-session handshake.
//
//   To verify, capture a 576-byte UDP frame from the Stick (UDP→192.168.96.2:2431,
//   live DMX from Hardware Manager) and try to decrypt its 544-byte body
//   (offset +0x20..+0x240) using AES-128-CBC and AES-128-CFB with these key/IV.
//   If either yields plaintext that looks like DMX (mostly 0s with a few
//   non-zero channel values), the hardcoded secret IS the key.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const KEY = Buffer.from('527a5b46c56f3a5e670b4f0e338727d9', 'hex');
const IV  = Buffer.from('4737ec0fc4af0dba93a51d93965191d0', 'hex');
// 33rd byte (0x8f) — meaning TBD; might be a mode flag or version byte.

if (process.argv.length < 3) {
  console.error('usage: tsx tools/try-hardcoded-key.ts <captured-576B-frame.bin>');
  console.error('  (capture with: tcpdump -i en0 -w stick.pcap udp port 2431,');
  console.error('   then extract the first 576-byte UDP payload as a raw .bin file)');
  process.exit(1);
}

const frame = fs.readFileSync(process.argv[2]);
if (frame.length !== 576) {
  console.error(`expected exactly 576 bytes, got ${frame.length}`);
  process.exit(1);
}

const header = frame.subarray(0, 0x20);     // 32 bytes clear
const body   = frame.subarray(0x20, 0x240); // 544 bytes encrypted

console.log('clear header (32B):');
console.log(' ', header.toString('hex').match(/../g)!.join(' '));
console.log(`  session_magic[0..8]    = ${header.subarray(0, 8).toString('hex')}`);
console.log(`  opcode/version[8..a]   = 0x${header.readUInt16LE(8).toString(16)}`);
console.log(`  field[a..12]           = ${header.subarray(0x0a, 0x12).toString('hex')}`);
console.log(`  field[12..14]          = 0x${header.readUInt16LE(0x12).toString(16)}`);
console.log(`  channel count[14..16]  = ${header.readUInt16LE(0x14)}`);
console.log(`  const100[16]           = 0x${header[0x16].toString(16)}`);
console.log(`  seq_counter[17]        = ${header[0x17]}`);
console.log(`  nonce[18..20]          = ${header.subarray(0x18, 0x20).toString('hex')}`);
console.log();
console.log('encrypted body length:', body.length, 'bytes (= 34 × 16B blocks)');
console.log();

function score(buf: Buffer): { zeroRatio: number; sample: string } {
  let zeros = 0;
  for (const b of buf) if (b === 0) zeros++;
  return {
    zeroRatio: zeros / buf.length,
    sample: buf.subarray(0, 32).toString('hex'),
  };
}

function tryDecrypt(label: string, algo: string, key: Buffer, iv: Buffer): void {
  try {
    const d = crypto.createDecipheriv(algo, key, iv);
    d.setAutoPadding(false);
    const out = Buffer.concat([d.update(body), d.final()]);
    const s = score(out);
    console.log(`${label}:`);
    console.log(`  zero ratio: ${(s.zeroRatio * 100).toFixed(1)}%   (DMX with mostly off lights should be high)`);
    console.log(`  first 32B:  ${s.sample}`);
  } catch (e: any) {
    console.log(`${label}: error: ${e.message}`);
  }
}

console.log('=== Trying hardcoded key, hardcoded IV ===');
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, IV);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, IV);

console.log();
console.log('=== Trying hardcoded key, nonce-as-IV (frame[+0x18..+0x20] zero-padded to 16B) ===');
const nonceIv = Buffer.concat([header.subarray(0x18, 0x20), Buffer.alloc(8)]);
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, nonceIv);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, nonceIv);

console.log();
console.log('=== Trying hardcoded key, full clear-header[16..32] as IV ===');
const headerTailIv = header.subarray(0x10, 0x20);
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, headerTailIv);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, headerTailIv);

console.log();
console.log('If any variant above shows >85% zeros + sensible DMX channel values,');
console.log('the hardcoded secret IS the key/IV — the plugin can encrypt without');
console.log('any per-session handshake. If none works, the handshake derives the');
console.log('key (see cipher vt[4]/[5]/[6] = opcodes 0xF/0x10/0x11).');
