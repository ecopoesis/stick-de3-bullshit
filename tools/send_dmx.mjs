#!/usr/bin/env node
// send_dmx — set DMX channels on a Nicolaudie Stick-DE3, transactionally.
//
//   node tools/send_dmx.mjs <ip> <universe,channel=value> [more…]
//   e.g.  node tools/send_dmx.mjs 192.168.96.2 0,22=8 0,1=255 0,6=128
//
// It connects to the Stick (TCP/2431), runs the handshake, derives the
// per-session AES key via the recovered KDF, sends the encrypted 576-byte
// DMX frame over UDP, then disconnects cleanly — relying on the Stick's
// "latch on clean disconnect" behaviour to hold the values.
//
// ── what is solid vs. hopeful ───────────────────────────────────────────────
//  SOLID  (verified): the KDF, the AES-256-CBC frame cipher, the 576-byte
//         frame layout, the fixed internal header P0. A frame built here is
//         byte-compatible with what Hardware Manager emits.
//  HOPEFUL (untested against hardware): the TCP handshake sequence is modelled
//         on a captured Hardware Manager session. The Stick may want more (or
//         fewer) messages, or may reject a partial handshake. Iterate from the
//         on-wire behaviour. The clean-disconnect latch is per the project
//         notes but only HWM has been observed doing it.
//
// channel is 1..512; value is 0..255; universe selects the DMX port field.

import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { makeEphemeral, deriveDmxKey, pointToWire, wireToPoint } from './derive-dmx-key.mjs';

const TCP_PORT = 2431;
const UDP_DST_PORT = 2431;
const UDP_SRC_PORT = 2430;
const MAGIC = Buffer.from('Stick_3A');
const LSAG = Buffer.from('LSAG_ALL');
// the 16-byte internal plaintext header — a fixed constant (RE-confirmed)
const P0 = Buffer.from('5b4e99da9685ad976c432b0a7ff9ffcc', 'hex');
// HMAC-SHA256 key for the 0x48 TCP-auth handshake — an internal Hardware
// Manager constant ("#h.6xcKsGD{y}-z"), extracted at runtime via
// tools/hmac-key.sh and verified against a captured HWM handshake.
const AUTH_KEY = Buffer.from('23682e3678634b7347447b797d2d7a', 'hex');
// the Stick's static 0x0F pubkey (constant across every observed session);
// used as a fallback if the live 0x0F reply can't be parsed.
const Q_FALLBACK = Buffer.from(
  '87ef58c2660c272b54a74bbc94cb8518108e370b7eed78456bd8d120c6b9ac0a' +
  'd791e4ce698aea761679f4b92a3ecf2acd12bf9bc308ce0ba8cb9663' + '0871105e', 'hex');

// ── args ────────────────────────────────────────────────────────────────────
const [, , ip, ...assigns] = process.argv;
if (!ip || assigns.length === 0) {
  console.error('usage: node tools/send_dmx.mjs <ip> <universe,channel=value> […]');
  process.exit(1);
}
// universe -> Uint8Array(512) of channel values
const universes = new Map();
for (const a of assigns) {
  const m = /^(\d+),(\d+)=(\d+)$/.exec(a.trim());
  if (!m) { console.error(`bad assignment: "${a}" (want universe,channel=value)`); process.exit(1); }
  const [u, ch, val] = [+m[1], +m[2], +m[3]];
  if (ch < 1 || ch > 512) { console.error(`channel ${ch} out of range 1..512`); process.exit(1); }
  if (val < 0 || val > 255) { console.error(`value ${val} out of range 0..255`); process.exit(1); }
  if (!universes.has(u)) universes.set(u, new Uint8Array(512));
  universes.get(u)[ch - 1] = val;
}

// ── tiny helpers ────────────────────────────────────────────────────────────
let tokenN = 0x80;
const token = () => { const b = Buffer.alloc(8); b.writeUInt32LE(tokenN++, 0); return b; };
const msg = (magic, opcode, ...parts) => {
  const op = Buffer.alloc(2); op.writeUInt16LE(opcode, 0);
  return Buffer.concat([magic, op, ...parts]);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// All received TCP bytes accumulate here for the life of the connection, so a
// reply already sitting in the buffer is never missed.
let rxBuf = Buffer.alloc(0);
const attachReader = (sock) => sock.on('data', (d) => { rxBuf = Buffer.concat([rxBuf, d]); });

/** find a Stick_3A/LSAG message with `opcode` and at least `minLen` bytes. */
function findMsg(opcode, minLen) {
  for (let o = 0; o + 10 <= rxBuf.length; o++) {
    if ((rxBuf.subarray(o, o + 8).equals(MAGIC) || rxBuf.subarray(o, o + 8).equals(LSAG)) &&
        rxBuf.readUInt16LE(o + 8) === opcode && rxBuf.length >= o + minLen) {
      return rxBuf.subarray(o, o + minLen);
    }
  }
  return null;
}
/** poll rxBuf until `predicate` returns non-null, or timeout. */
function waitFor(predicate, timeoutMs) {
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

// ── the DMX frame builder (verified format) ─────────────────────────────────
let seqCtr = 0;
function buildFrame(key, channels512, port) {
  // fieldA (+0x0a) is the SAME session message counter as the TCP tokens —
  // the UDP DMX frames continue the sequence. A counter that jumps backwards
  // (a separate low-valued counter) makes the Stick drop every frame.
  const fieldA = token();
  const nonce = crypto.randomBytes(8);
  const iv = Buffer.concat([fieldA, nonce]);                       // 16-byte CBC IV
  const plain = Buffer.concat([P0, Buffer.from(channels512), Buffer.alloc(16)]); // 544
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  c.setAutoPadding(false);
  const body = Buffer.concat([c.update(plain), c.final()]);        // 544
  const hdr = Buffer.alloc(32);
  MAGIC.copy(hdr, 0);
  hdr.writeUInt16LE(0x0019, 8);
  fieldA.copy(hdr, 0x0a);
  hdr.writeUInt16LE(port, 0x12);
  hdr.writeUInt16LE(512, 0x14);
  hdr[0x16] = 100;
  hdr[0x17] = seqCtr++ & 0xff;
  nonce.copy(hdr, 0x18);
  return Buffer.concat([hdr, body]);                              // 576
}

// ── main ────────────────────────────────────────────────────────────────────
const log = (...a) => console.log('  ', ...a);

async function handshake(sock) {
  attachReader(sock);

  // 1. 0x47 — LSAG_ALL hello; the Stick replies with its 32-byte handshake key
  sock.write(msg(LSAG, 0x47, token()));
  const r47 = await waitFor(() => findMsg(0x47, 54), 3000);
  let stickKey = Buffer.alloc(32);
  if (r47 != null) {
    stickKey = Buffer.from(r47.subarray(0x16, 0x36));   // Stick handshake key
    log('0x47 ok — got Stick handshake key');
  } else log('0x47 — no reply (continuing)');

  // 2. 0x48 — authenticated handshake. The message is
  //      magic(8) ‖ 0x48 ‖ token(8) ‖ softwareName(32) ‖ stickKey(32)
  //    followed by HMAC-SHA256(AUTH_KEY, that 82-byte head). The Stick
  //    verifies the HMAC; a bad one => reply status 100 (PermissionDenied)
  //    and the session is never promoted to a live control session.
  const software = Buffer.alloc(32); software.write('software');
  const head48 = msg(LSAG, 0x48, token(), software, stickKey);   // 82 bytes
  const mac48 = crypto.createHmac('sha256', AUTH_KEY).update(head48).digest();
  sock.write(Buffer.concat([head48, mac48]));                    // 114 bytes
  const r48 = await waitFor(() => findMsg(0x48, 22), 2000);
  if (r48) {
    const st = r48.readUInt32LE(0x12);
    log(`0x48 auth status: ${st}` + (st === 0 ? ' (ok)' : ' (REJECTED)'));
  } else log('0x48 — no reply');

  // 3. observed pre-DMX chatter — sent ONE AT A TIME. HWM never batches these;
  //    a single coalesced TCP segment leaves the Stick without sending its
  //    0xc9 status, i.e. it never registers the session as a live client.
  for (const m of [
    msg(MAGIC, 0x46, Buffer.alloc(4)),
    msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')),
    msg(MAGIC, 0x011c, token(), Buffer.from('01001600', 'hex')),
    msg(MAGIC, 0x05, Buffer.from('0200', 'hex')),
  ]) {
    sock.write(m);
    await sleep(140);   // separate segment + let the Stick reply
  }
  if (findMsg(0x00c9, 18)) log('0xc9 status received — Stick registered the session');

  // 4. 0x10 — crypto-state query. HWM sees state 3 on a fresh device; state 4
  //    means a DMX key from a previous session is still latched.
  rxBuf = Buffer.alloc(0);
  sock.write(msg(MAGIC, 0x10, token()));
  const r10 = await waitFor(() => findMsg(0x10, 22), 2000);
  if (r10) log(`0x10 crypto state: ${r10.readUInt32LE(0x12)}`);
  rxBuf = Buffer.alloc(0);

  // 5. 0x0F — the DMX key exchange: send our P-256 ephemeral pubkey
  const ecdh = makeEphemeral();
  const ourP256 = pointToWire(ecdh.getPublicKey(null, 'uncompressed'));  // 64-byte wire form
  sock.write(msg(MAGIC, 0x0f, token(), ourP256));
  const r0f = await waitFor(() => findMsg(0x0f, 86), 3000);
  let Qwire = Q_FALLBACK;
  if (r0f != null) {
    Qwire = r0f.subarray(0x16, 0x56);   // Stick DMX pubkey, 64-byte wire form
    log('0x0F ok — got Stick DMX pubkey');
  } else log('0x0F — no reply, using known static Stick key');

  // 6. derive the DMX session key (KDF: P-256 double-ECDH)
  const key = deriveDmxKey(ecdh, wireToPoint(Qwire));
  log('DMX key derived:', key.toString('hex'));
  // dump key + ephemeral private d so a capture can be decrypted offline and
  // verified — proving whether our own frames are validly encrypted.
  try {
    const dHex = ecdh.getPrivateKey('hex');
    fs.writeFileSync('/tmp/send_dmx-key.txt',
      `key=${key.toString('hex')}\nd=${dHex}\nQ=${Qwire.toString('hex')}\n`);
    log('wrote /tmp/send_dmx-key.txt');
  } catch (e) { log('key dump failed:', e.message); }

  // 6b. device sync — replicated to match a captured HWM session BYTE-FOR-BYTE
  //     in both ORDER and CONTENT (verified against tools/analyze-pcap.mjs):
  //       0x10, 0x75, 0x74, 0x71×3, 0x70 download, 0x2e
  //     The earlier code did 0x75/0x74 AFTER the download and sent the wrong
  //     third 0x71 param — both now corrected.
  sock.write(msg(MAGIC, 0x10, token())); await sleep(120);
  sock.write(msg(MAGIC, 0x75, token())); await sleep(140);
  sock.write(msg(MAGIC, 0x74, token())); await sleep(140);
  // HWM's 0x71 params (from the 2026-05-23 mirror capture of a working
  // session): FOUR reads — 0200000000, 0100000000, 0100000000, 02b37f0000.
  // The 4th was missing in the earlier code (only seen via the port mirror
  // at the Stick) and the 3rd's value varies between HWM sessions, so it
  // looks tolerant — but the 4th is the one opcode pattern HWM emits that
  // we never did, so include it.
  for (const p of ['0200000000', '0100000000', '0100000000', '02b37f0000']) {
    sock.write(msg(MAGIC, 0x71, token(), Buffer.from(p, 'hex')));
    await sleep(80);
  }
  // exact 0x70 sequence HWM session 64448 sends: sector 0, then 63..185
  // (124 reads, flag byte = 1). The earlier 0..255 sequential read diverged.
  const sectors = [0];
  for (let s = 63; s <= 185; s++) sectors.push(s);
  log(`0x70 device download (${sectors.length} sectors, HWM-exact) …`);
  for (let i = 0; i < sectors.length; i++) {
    const body = Buffer.alloc(5);
    body.writeUInt32LE(sectors[i], 0);
    body[4] = 1;
    sock.write(msg(MAGIC, 0x70, token(), body));
    await sleep(12);
    if ((i & 0x1f) === 0x1f) rxBuf = Buffer.alloc(0);   // keep rxBuf bounded
  }
  await sleep(200);
  rxBuf = Buffer.alloc(0);

  // 7. enter live mode: 0x2e, then a settle gap, then 0x10/0x11/0x10. HWM
  //    waits ~3.7 s between 0x2e and 0x10/0x11; we use a shorter settle.
  sock.write(msg(MAGIC, 0x2e, Buffer.alloc(32))); await sleep(140);  // 0x2e: 32B payload, no token
  await sleep(800);                                      // settle (HWM gap)
  sock.write(msg(MAGIC, 0x10, token())); await sleep(140);
  sock.write(msg(MAGIC, 0x11, token()));                 // "go live"
  const r11 = await waitFor(() => findMsg(0x11, 22), 3000);
  log(r11 ? 'live mode enabled (0x11 ok)' : '0x11 — no reply (streaming anyway)');
  sock.write(msg(MAGIC, 0x10, token()));                 // HWM does a 0x10 after 0x11
  const r10b = await waitFor(() => findMsg(0x10, 22), 1500);
  if (r10b) log(`0x10 after 0x11 — crypto state ${r10b.readUInt32LE(0x12)} (HWM sees 4)`);
  return key;
}

// HWM emits four 14-byte UDP/2430 broadcasts at startup (LSAG_ALL,
// Stick_U1, Stick_3A, Siudi_7B), three times in a row, BEFORE any TCP. Each
// body = magic(8) + 0x0000 + 0x14000000.
const DISCOVERY_MAGICS = ['LSAG_ALL', 'Stick_U1', 'Stick_3A', 'Siudi_7B'];
const DISCOVERY_TAIL = Buffer.from('000014000000', 'hex');
async function discoveryBroadcast(udp) {
  for (let burst = 0; burst < 3; burst++) {
    for (const m of DISCOVERY_MAGICS) {
      const pkt = Buffer.concat([Buffer.from(m, 'ascii'), DISCOVERY_TAIL]);
      await new Promise((r) => udp.send(pkt, 2430, '255.255.255.255', () => r()));
    }
    await sleep(25);
  }
}

// HWM also broadcasts a SEPARATE "I am Hardware Manager" announcement on
// UDP/24299 (src+dst 24299) with magic "LIGHTINGSOFT_XHL". A 114-byte
// announce carrying the literal string "Hardware Manager", followed by
// 46-byte status follow-ups. The 8-byte instance ID is fresh per launch.
// We have no Stick-side traffic acknowledging these but HWM does them
// consistently, so they may be what the Stick uses to identify a client as
// the live controller.
const XHL_HEADER = Buffer.from(
  '4c49474854494e47534f46545f58484c' +  // "LIGHTINGSOFT_XHL"
  '0000000000000000' +                   // 8B zero padding
  '14000000' +                           // op/len = 20
  '01000000',                            // version = 1
  'hex');                                // 32B total
async function announceHardwareManager(udp24299, instanceId) {
  // 114B "I am Hardware Manager" announce
  const body114 = Buffer.alloc(114 - 32);
  instanceId.copy(body114, 0);                          // [32:40] instance
  body114.writeUInt32LE(crypto.randomBytes(4).readUInt32LE(0), 8);  // [40:44] varying
  body114.writeUInt32LE(11, 12);                        // [44:48] = 0x0b
  body114.write('Hardware Manager\0', 18, 'ascii');     // [50:67] string
  const pkt114 = Buffer.concat([XHL_HEADER, body114]);
  await new Promise((r) => udp24299.send(pkt114, 24299, '255.255.255.255', () => r()));
  await sleep(25);
  // 2 × 46B follow-ups
  for (let i = 0; i < 2; i++) {
    const tail = Buffer.concat([crypto.randomBytes(4), Buffer.from([0x0a + i * 2, 0])]);
    const pkt46 = Buffer.concat([XHL_HEADER, instanceId, tail]);
    await new Promise((r) => udp24299.send(pkt46, 24299, '255.255.255.255', () => r()));
    await sleep(25);
  }
}

async function main() {
  console.log(`send_dmx → ${ip}`);
  // 0. UDP socket up FIRST — for discovery + the live DMX stream
  const udp = dgram.createSocket('udp4');
  await new Promise((res, rej) => {
    udp.once('error', rej);
    udp.bind(UDP_SRC_PORT, () => { udp.setBroadcast(true); res(); });
  });
  log(`UDP socket bound to ${UDP_SRC_PORT}, broadcast enabled`);
  await discoveryBroadcast(udp);
  log('discovery broadcasts sent (LSAG_ALL/Stick_U1/Stick_3A/Siudi_7B × 3)');

  // open a 2nd UDP socket bound to port 24299 for the LIGHTINGSOFT_XHL announce
  const udp24299 = dgram.createSocket('udp4');
  await new Promise((res, rej) => {
    udp24299.once('error', rej);
    udp24299.bind(24299, () => { udp24299.setBroadcast(true); res(); });
  });
  const instanceId = crypto.randomBytes(8);
  await announceHardwareManager(udp24299, instanceId);
  log(`LIGHTINGSOFT_XHL "Hardware Manager" announce sent (instance ${instanceId.toString('hex')})`);
  udp24299.close();                                     // done with it — prevents process hang
  await sleep(200);

  const sock = net.createConnection({ host: ip, port: TCP_PORT });
  sock.on('error', (e) => { console.error('TCP error:', e.message); process.exit(1); });
  sock.setTimeout(5000);
  await new Promise((res, rej) => {
    sock.once('connect', res);
    sock.once('error', rej);
    sock.once('timeout', () => rej(new Error(`no response from ${ip}:${TCP_PORT} (timeout)`)));
  });
  sock.setTimeout(0);
  log('TCP connected');

  const key = await handshake(sock);

  // (UDP socket already opened at the top of main() for discovery; reused here)
  for (const [u, chans] of universes) {
    const lit = [...chans.entries()].filter(([, v]) => v).map(([i, v]) => `ch${i + 1}=${v}`);
    log(`universe ${u}: ${lit.join(' ') || '(all 0)'}`);
  }
  // stream with INDEPENDENT steady timers, mirroring HWM's architecture: HWM
  // runs the UDP DMX stream on its own rock-steady 25 Hz timer thread, with
  // the TCP heartbeat on a separate thread. The earlier single-loop coupled
  // them — it hitched the UDP stream for the heartbeat round-trip every
  // second and ran at ~27 Hz. A live-stream detector on the Stick may want a
  // genuine steady 25 Hz; this removes that as a variable.
  sock.write(msg(MAGIC, 0x10, token()));
  const STREAM_MS = Number(process.env.STREAM_MS || 20000);
  let nFrames = 0, beats = 0;

  const udpTimer = setInterval(() => {                 // 25 Hz, exactly like HWM
    for (const [u, chans] of universes) {
      udp.send(buildFrame(key, chans, u), UDP_DST_PORT, ip, () => {});
      nFrames++;
    }
  }, 40);

  const hbTimer = setInterval(() => {                  // 1 Hz TCP keepalive
    rxBuf = Buffer.alloc(0);
    sock.write(msg(MAGIC, 0x1a, token(), Buffer.alloc(2)));   // 20-byte heartbeat
    waitFor(() => findMsg(0x1a, 44), 800).then((hb) => {
      // the 0x1a reply's last 4 bytes [+0x28] are a flag: HWM sees 1 once it
      // is the live DMX source; we have only ever seen 0. That flag is the goal.
      if (hb) log(`heartbeat ${beats++}: liveFlag[+0x28]=${hb.readUInt32LE(40)} ` +
                  `counter[+0x26]=${hb.readUInt32LE(38)}`);
      else log(`heartbeat ${beats++}: no reply`);
    });
  }, 1000);

  const p12Timer = setInterval(() => {                 // HWM's ~0.1 Hz 0x12 poll
    sock.write(msg(MAGIC, 0x12, token()));
  }, 10000);

  await sleep(STREAM_MS);
  clearInterval(udpTimer); clearInterval(hbTimer); clearInterval(p12Timer);
  log(`streamed ${nFrames} frames + ${beats} heartbeats over ${STREAM_MS}ms`);

  udp.close();
  // clean TCP disconnect → the Stick latches the last DMX values
  await new Promise((res) => sock.end(res));
  log('disconnected cleanly — Stick should hold the values');
}

main().catch((e) => { console.error('failed:', e.message); process.exit(1); });
