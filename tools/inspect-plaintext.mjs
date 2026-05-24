// Decrypt every 576-byte UDP DMX frame in a pcap and dump the FULL 544-byte
// plaintext layout: [0:16] P0 header, [16:528] 512 DMX, [528:544] trailer.
// The question: is the 16-byte trailer zero (what send_dmx sends) or a
// per-frame checksum the Stick validates?
//
//   node tools/inspect-plaintext.mjs <pcap> <key-hex>

import fs from 'node:fs';
import crypto from 'node:crypto';

const [, , pcapPath, keyHex] = process.argv;
if (!pcapPath || !keyHex) { console.error('usage: inspect-plaintext.mjs <pcap> <key-hex>'); process.exit(1); }
const key = Buffer.from(keyHex.replace(/\s/g, ''), 'hex');
if (key.length !== 32) { console.error('key must be 32 bytes'); process.exit(1); }

const buf = fs.readFileSync(pcapPath);
const le = buf.readUInt32LE(0) === 0xa1b2c3d4;
const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
const ethSkip = linkType === 1 ? 14 : 4;

const frames = [];
let off = 24;
while (off + 16 <= buf.length) {
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  if (pkt.length < ethSkip + 28) continue;
  const ip = pkt.subarray(ethSkip);
  if (ip[9] !== 17) continue;
  const udp = ip.subarray((ip[0] & 0x0f) * 4);
  const payload = udp.subarray(8, udp.readUInt16BE(4));
  if (payload.length === 576 && payload.subarray(0, 8).toString() === 'Stick_3A')
    frames.push(Buffer.from(payload));
}
console.log(`${frames.length} 576-byte frames in ${pcapPath}\n`);

function decrypt(frame) {
  const h = frame.subarray(0, 32);
  const iv = Buffer.concat([h.subarray(0x0a, 0x12), h.subarray(0x18, 0x20)]);
  const d = crypto.createDecipheriv('aes-256-cbc', key, iv);
  d.setAutoPadding(false);
  return Buffer.concat([d.update(frame.subarray(32)), d.final()]);
}
const zr = (b) => { let z = 0; for (const x of b) if (x === 0) z++; return z / b.length; };

let decoded = 0;
const p0set = new Map(), trailerSet = new Map();
const trailerSamples = [];
for (let i = 0; i < frames.length; i++) {
  const pt = decrypt(frames[i]);
  const dmx = pt.subarray(16, 528);
  if (zr(dmx) < 0.5) continue;             // not this session's key
  decoded++;
  const p0 = pt.subarray(0, 16).toString('hex');
  const tr = pt.subarray(528, 544).toString('hex');
  p0set.set(p0, (p0set.get(p0) || 0) + 1);
  trailerSet.set(tr, (trailerSet.get(tr) || 0) + 1);
  if (decoded <= 6) {
    const h = frames[i].subarray(0, 32);
    const lit = [];
    for (let c = 0; c < 512; c++) if (dmx[c]) lit.push(`ch${c+1}=${dmx[c]}`);
    trailerSamples.push({
      fieldA: h.readUInt32LE(0x0a), seq: h[0x17],
      p0, tr, nLit: lit.length, lit: lit.slice(0, 8).join(' '),
    });
  }
}

console.log(`frames that decrypt with this key: ${decoded}/${frames.length}\n`);
if (!decoded) { console.log('key does not match any frame in this pcap'); process.exit(1); }

console.log('first 6 decrypted frames:');
for (const s of trailerSamples) {
  console.log(`  fieldA=${String(s.fieldA).padEnd(6)} seq=${String(s.seq).padEnd(4)} lit=${s.nLit}`);
  console.log(`    P0      = ${s.p0}`);
  console.log(`    trailer = ${s.tr}`);
  if (s.lit) console.log(`    dmx     = ${s.lit}`);
}
console.log(`\nP0 distinct values    : ${p0set.size}`);
for (const [v, n] of p0set) console.log(`    ${v}  x${n}`);
console.log(`trailer distinct values: ${trailerSet.size}`);
for (const [v, n] of [...trailerSet].slice(0, 8)) console.log(`    ${v}  x${n}`);
console.log(trailerSet.size === 1
  ? '\n  => trailer is CONSTANT — send_dmx sending zeros is wrong only if this constant != 0'
  : '\n  => trailer VARIES per frame — it is a checksum/MAC; send_dmx sending zeros is FATAL');
