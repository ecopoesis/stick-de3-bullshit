// Try decrypting a captured 576-byte DMX frame using the hardcoded 33-byte
// secret discovered by Ghidra static RE.
//
// See tools/try-hardcoded-key.ts (TS twin) for the full backstory. This .mjs
// version is plain Node so it runs without tsx.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';

const KEY = Buffer.from('527a5b46c56f3a5e670b4f0e338727d9', 'hex');
const IV  = Buffer.from('4737ec0fc4af0dba93a51d93965191d0', 'hex');

if (process.argv.length < 3) {
  console.error('usage: node tools/try-hardcoded-key.mjs <captured-576B-frame.bin>');
  process.exit(1);
}

const frame = fs.readFileSync(process.argv[2]);
if (frame.length !== 576) {
  console.error(`expected exactly 576 bytes, got ${frame.length}`);
  process.exit(1);
}

const header = frame.subarray(0, 0x20);
const body   = frame.subarray(0x20, 0x240);

console.log('clear header (32B):');
console.log(' ', header.toString('hex').match(/../g).join(' '));
console.log(`  session_magic[0..8]    = ${header.subarray(0, 8).toString('hex')}`);
console.log(`  opcode/ver[8..a]       = 0x${header.readUInt16LE(8).toString(16)}`);
console.log(`  field[a..12]           = ${header.subarray(0x0a, 0x12).toString('hex')}`);
console.log(`  field[12..14]          = 0x${header.readUInt16LE(0x12).toString(16)}`);
console.log(`  channel count[14..16]  = ${header.readUInt16LE(0x14)}`);
console.log(`  const100[16]           = 0x${header[0x16].toString(16)}`);
console.log(`  seq_counter[17]        = ${header[0x17]}`);
console.log(`  nonce[18..20]          = ${header.subarray(0x18, 0x20).toString('hex')}`);
console.log();

function score(buf) {
  let zeros = 0;
  for (const b of buf) if (b === 0) zeros++;
  return {
    zeroRatio: zeros / buf.length,
    sample: buf.subarray(0, 48).toString('hex'),
  };
}

function tryDecrypt(label, algo, key, iv) {
  try {
    const d = crypto.createDecipheriv(algo, key, iv);
    d.setAutoPadding(false);
    const out = Buffer.concat([d.update(body), d.final()]);
    const s = score(out);
    console.log(`${label}:`);
    console.log(`  zero ratio: ${(s.zeroRatio * 100).toFixed(1)}%   (DMX with mostly off lights should be ~95%)`);
    console.log(`  first 48B:  ${s.sample}`);
  } catch (e) {
    console.log(`${label}: error: ${e.message}`);
  }
}

console.log('=== Variant A: hardcoded key + hardcoded IV ===');
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, IV);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, IV);

console.log();
console.log('=== Variant B: hardcoded key + nonce-as-IV (frame[+0x18..+0x20] zero-padded) ===');
const nonceIv = Buffer.concat([header.subarray(0x18, 0x20), Buffer.alloc(8)]);
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, nonceIv);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, nonceIv);

console.log();
console.log('=== Variant C: hardcoded key + full clear-header[16..32] as IV ===');
const headerTailIv = header.subarray(0x10, 0x20);
tryDecrypt('AES-128-CBC', 'aes-128-cbc', KEY, headerTailIv);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', KEY, headerTailIv);

console.log();
console.log('=== Variant D: hardcoded IV used as the key, hardcoded key used as IV ===');
tryDecrypt('AES-128-CBC', 'aes-128-cbc', IV, KEY);
tryDecrypt('AES-128-CFB', 'aes-128-cfb', IV, KEY);

console.log();
console.log('If any variant above shows zero-ratio > 85% + plausible DMX values,');
console.log('the hardcoded secret IS the key/IV. If none works, the handshake');
console.log("derives the key per-session (cipher's vt[4/5/6] = opcodes 0xF/0x10/0x11).");
