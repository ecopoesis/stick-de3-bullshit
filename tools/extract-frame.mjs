// Extract one 576-byte DMX payload from a tcpdump pcap file.
//
// pcap format (libpcap, little-endian):
//   24-byte global header  (magic d4c3b2a1 or a1b2c3d4)
//   per-packet records:
//     16-byte record header (ts_sec, ts_usec, cap_len, orig_len)
//     <cap_len> bytes of raw frame (ethernet+IP+UDP+payload)
//
// We look for any packet whose IP/UDP demux says: dst=STICK_IP:STICK_PORT
// and UDP payload length == 576.

import fs from 'node:fs';

const STICK_IP   = process.env.STICK_IP   || '192.168.96.2';
const STICK_PORT = Number(process.env.STICK_PORT || 2431);

const [, , pcapPath, outPath] = process.argv;
if (!pcapPath || !outPath) {
  console.error('usage: node tools/extract-frame.mjs <input.pcap> <output.bin>');
  process.exit(1);
}

const buf = fs.readFileSync(pcapPath);
if (buf.length < 24) { console.error('pcap too small'); process.exit(2); }

// Magic constant `0xa1b2c3d4` is written in the writer's native byte order.
// Reading the first 4 bytes as LE: 0xa1b2c3d4 -> file is LE
//                                  0xd4c3b2a1 -> file is BE
const magic = buf.readUInt32LE(0);
let le;
if      (magic === 0xa1b2c3d4) le = true;
else if (magic === 0xd4c3b2a1) le = false;
else { console.error(`unknown pcap magic 0x${magic.toString(16)}`); process.exit(2); }

const linkType = le ? buf.readUInt32LE(20) : buf.readUInt32BE(20);
// linkType 1 = Ethernet, 0 = BSD loopback / NULL header (4 bytes)
const ethSkip = (linkType === 1) ? 14 : (linkType === 0 ? 4 : 14);

let off = 24;
let pkts = 0, matched = 0;
while (off + 16 <= buf.length) {
  const tsSec  = le ? buf.readUInt32LE(off)     : buf.readUInt32BE(off);
  const tsUsec = le ? buf.readUInt32LE(off + 4) : buf.readUInt32BE(off + 4);
  const capLen = le ? buf.readUInt32LE(off + 8) : buf.readUInt32BE(off + 8);
  off += 16;
  if (off + capLen > buf.length) break;
  pkts++;
  const pkt = buf.subarray(off, off + capLen);
  off += capLen;

  // Parse Ethernet/Null + IPv4 + UDP
  if (pkt.length < ethSkip + 28) continue;
  const ip = pkt.subarray(ethSkip);
  const ihl = (ip[0] & 0x0f) * 4;
  const proto = ip[9];
  if (proto !== 17) continue; // not UDP

  const srcIp = `${ip[12]}.${ip[13]}.${ip[14]}.${ip[15]}`;
  const dstIp = `${ip[16]}.${ip[17]}.${ip[18]}.${ip[19]}`;
  const udp = ip.subarray(ihl);
  if (udp.length < 8) continue;
  const srcPort = udp.readUInt16BE(0);
  const dstPort = udp.readUInt16BE(2);
  const udpLen  = udp.readUInt16BE(4);
  const payload = udp.subarray(8, udpLen);

  if (dstIp === STICK_IP && dstPort === STICK_PORT) {
    matched++;
    console.error(`  match #${matched}: ${srcIp}:${srcPort} -> ${dstIp}:${dstPort}  payload=${payload.length}B`);
    if (payload.length === 576) {
      fs.writeFileSync(outPath, payload);
      console.error(`OK: wrote 576-byte payload to ${outPath}`);
      process.exit(0);
    }
  }
}
console.error(`scanned ${pkts} packets, ${matched} matched dst, no 576B payload found`);
process.exit(3);
