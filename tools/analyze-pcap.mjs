// Deep analysis of a Stick-DE3 pcap: TCP connections + per-connection opcode
// timeline, and UDP DMX-frame header statistics (fieldA / seq progression,
// the +0x12 port field, timing). Built to diff a real Hardware Manager
// session against our send_dmx run.
//
//   node tools/analyze-pcap.mjs <file.pcap>

import fs from 'node:fs';

const [, , pcapPath] = process.argv;
if (!pcapPath) { console.error('usage: node tools/analyze-pcap.mjs <file.pcap>'); process.exit(1); }

const buf = fs.readFileSync(pcapPath);
const magic = buf.readUInt32LE(0);
const le = magic === 0xa1b2c3d4;
if (!le && magic !== 0xd4c3b2a1) { console.error('bad pcap'); process.exit(2); }
const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
const ethSkip = linkType === 1 ? 14 : 4;

const pkts = [];
let off = 24;
while (off + 16 <= buf.length) {
  const tsSec = le ? buf.readUInt32LE(off) : buf.readUInt32BE(off);
  const tsUsec = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;
  if (pkt.length < ethSkip + 20) continue;
  const ip = pkt.subarray(ethSkip);
  if (((ip[0] >> 4) & 0xf) !== 4) continue;
  const ihl = (ip[0] & 0x0f) * 4;
  const proto = ip[9];
  const src = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
  const dst = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const l4 = ip.subarray(ihl);
  const t = tsSec + tsUsec / 1e6;
  if (proto === 6) {
    const sp = l4.readUInt16BE(0), dp = l4.readUInt16BE(2);
    const flags = l4[13];
    const dataOff = (l4[12] >> 4) * 4;
    pkts.push({ t, proto: 'TCP', src, dst, sp, dp, flags, payload: Buffer.from(l4.subarray(dataOff)) });
  } else if (proto === 17) {
    const sp = l4.readUInt16BE(0), dp = l4.readUInt16BE(2);
    const ulen = l4.readUInt16BE(4) - 8;
    pkts.push({ t, proto: 'UDP', src, dst, sp, dp, payload: Buffer.from(l4.subarray(8, 8 + ulen)) });
  }
}

const t0 = pkts.length ? pkts[0].t : 0;
const rel = (t) => (t - t0).toFixed(3).padStart(9);

// ── TCP connections ─────────────────────────────────────────────────────────
console.log(`\n=== ${pcapPath} ===`);
console.log(`${pkts.length} IP packets, span ${(pkts[pkts.length-1].t - t0).toFixed(1)}s\n`);

const conns = new Map();
for (const p of pkts) {
  if (p.proto !== 'TCP') continue;
  const key = [p.src + ':' + p.sp, p.dst + ':' + p.dp].sort().join(' <-> ');
  if (!conns.has(key)) conns.set(key, []);
  conns.get(key).push(p);
}
console.log(`TCP connections: ${conns.size}`);
for (const [key, ps] of conns) {
  const dur = ps[ps.length - 1].t - ps[0].t;
  const dataP = ps.filter((p) => p.payload.length > 0);
  console.log(`\n  ${key}   start=${rel(ps[0].t)}s  dur=${dur.toFixed(3)}s  pkts=${ps.length} (${dataP.length} w/ payload)`);
  for (const p of dataP) {
    const dir = p.sp === 2431 ? 'S->C' : 'C->S';
    let op = '';
    const pl = p.payload;
    if (pl.length >= 10 && (pl.subarray(0,8).toString()==='Stick_3A' || pl.subarray(0,8).toString()==='LSAG_ALL')) {
      op = `op=0x${pl.readUInt16LE(8).toString(16).padStart(4,'0')}`;
    }
    console.log(`    ${rel(p.t)}  ${dir}  ${String(pl.length).padStart(4)}B  ${op.padEnd(11)} ${pl.subarray(0,28).toString('hex')}`);
  }
}

// ── UDP DMX frames ──────────────────────────────────────────────────────────
const dmx = pkts.filter((p) => p.proto === 'UDP' && p.payload.length === 576);
console.log(`\n\nUDP 576-byte DMX frames: ${dmx.length}`);
if (dmx.length) {
  const f = dmx[0], h = f.payload;
  console.log(`  src ${f.src}:${f.sp} -> dst ${f.dst}:${f.dp}`);
  console.log(`  first frame header (32B): ${h.subarray(0,32).toString('hex')}`);
  const fieldA0 = h.readUInt32LE(0x0a);
  console.log(`  +0x08 opcode    = 0x${h.readUInt16LE(8).toString(16)}`);
  console.log(`  +0x0a fieldA    = ${fieldA0} (0x${fieldA0.toString(16)})  [8B: ${h.subarray(0x0a,0x12).toString('hex')}]`);
  console.log(`  +0x12 port      = ${h.readUInt16LE(0x12)}`);
  console.log(`  +0x14 chanCount = ${h.readUInt16LE(0x14)}`);
  console.log(`  +0x16 const     = ${h[0x16]}`);
  console.log(`  +0x17 seq       = ${h[0x17]}`);
  console.log(`  +0x18 nonce     = ${h.subarray(0x18,0x20).toString('hex')}`);

  // progressions
  let dT = [], dA = [], dS = [], ports = new Set(), chans = new Set();
  for (let i = 1; i < dmx.length; i++) {
    dT.push(dmx[i].t - dmx[i-1].t);
    let a = dmx[i].payload.readUInt32LE(0x0a) - dmx[i-1].payload.readUInt32LE(0x0a);
    let s = dmx[i].payload[0x17] - dmx[i-1].payload[0x17];
    if (s < 0) s += 256;
    dA.push(a); dS.push(s);
  }
  for (const p of dmx) { ports.add(p.payload.readUInt16LE(0x12)); chans.add(p.payload.readUInt16LE(0x14)); }
  const uniq = (arr) => [...new Set(arr)].sort((a,b)=>a-b);
  const avg = (arr) => arr.reduce((s,x)=>s+x,0)/arr.length;
  console.log(`\n  fieldA delta/frame : ${uniq(dA).join(',')}   (start ${fieldA0}, end ${dmx[dmx.length-1].payload.readUInt32LE(0x0a)})`);
  console.log(`  seq    delta/frame : ${uniq(dS).join(',')}`);
  console.log(`  +0x12 port values  : ${[...ports].join(',')}`);
  console.log(`  +0x14 chanCount    : ${[...chans].join(',')}`);
  console.log(`  inter-frame gap    : avg ${(avg(dT)*1000).toFixed(1)}ms  (${(1/avg(dT)).toFixed(1)} Hz)`);
  console.log(`  first DMX frame at : ${rel(dmx[0].t)}s    last at ${rel(dmx[dmx.length-1].t)}s`);

  // ── unified-counter contiguity check ──────────────────────────────────────
  // HWM draws fieldA (UDP) and the TCP token from ONE monotonic counter.
  // Build a merged time-ordered list of (TCP token) + (UDP fieldA) and verify
  // the UDP frames continue the TCP token sequence without going backwards.
  const tcpTok = [];
  for (const p of pkts) {
    if (p.proto !== 'TCP' || p.payload.length < 18) continue;
    const m = p.payload.subarray(0, 8).toString();
    if (m !== 'Stick_3A' && m !== 'LSAG_ALL') continue;
    if (p.sp === 2431) continue;                       // client->Stick only
    const op = p.payload.readUInt16LE(8);
    tcpTok.push({ t: p.t, kind: 'TCP', op, val: p.payload.readUInt32LE(10) });
  }
  const merged = [...tcpTok, ...dmx.map((p) => ({ t: p.t, kind: 'UDP', val: p.payload.readUInt32LE(0x0a) }))]
    .sort((a, b) => a.t - b.t);
  // last TCP token before the first UDP frame
  const firstUdpT = dmx[0].t;
  const tcpBefore = tcpTok.filter((x) => x.t < firstUdpT);
  const lastTok = tcpBefore.length ? tcpBefore[tcpBefore.length - 1].val : null;
  console.log(`\n  unified counter:`);
  console.log(`    last TCP token before 1st UDP frame : ${lastTok}`);
  console.log(`    first UDP fieldA                    : ${dmx[0].payload.readUInt32LE(0x0a)}`);
  let backwards = 0, prev = -1;
  for (const e of merged) { if (e.val < prev) backwards++; prev = Math.max(prev, e.val); }
  const contiguous = lastTok != null && dmx[0].payload.readUInt32LE(0x0a) === lastTok + 1;
  console.log(`    UDP fieldA == lastTCPtoken + 1 ?    : ${contiguous ? 'YES' : 'NO'}`);
  console.log(`    backwards steps in merged sequence  : ${backwards} ${backwards ? '<-- Stick will drop these' : '(monotonic OK)'}`);
}
