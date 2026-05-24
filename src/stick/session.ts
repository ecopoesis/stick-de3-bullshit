// StickSession — TCP/2431 control channel + UDP/2431 encrypted DMX stream.
//
// Lifecycle:
//   const session = await StickSession.connect(ip);
//   session.send(channels, universe);     // one DMX frame
//   // ...repeat at 25 Hz...
//   session.destroy();                     // RST → Stick latches last values
//
// Ported from tools/send_dmx.mjs (frozen reference). Every env-var knob that
// existed in the .mjs is now a SessionOpts field with the same default; the
// env var remains as fallback so the CLI keeps its existing tuning behaviour.

import net from 'node:net';
import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { Buffer } from 'node:buffer';

import {
  AUTH_KEY,
  LSAG,
  MAGIC,
  Q_FALLBACK,
  TCP_PORT,
  Token,
  UDP_DST_PORT,
  UDP_SRC_PORT,
  findMsg,
  msg,
  sleep,
  waitFor,
} from './protocol.js';

// HWM-faithful UDP broadcasts. 4 magics × 3 bursts on UDP/2430, plus a
// "LIGHTINGSOFT_XHL Hardware Manager" announce on UDP/24299. Verified
// 2026-05-24: not optional — without them, sessions after a Stick
// power-cycle silently fail to actually drive output even though the
// TCP handshake reports go-live success.
const DISCOVERY_MAGICS = ['LSAG_ALL', 'Stick_U1', 'Stick_3A', 'Siudi_7B'];
const DISCOVERY_TAIL = Buffer.from('000014000000', 'hex');

async function discoveryBroadcast(udp: dgram.Socket): Promise<void> {
  for (let burst = 0; burst < 3; burst++) {
    for (const m of DISCOVERY_MAGICS) {
      const pkt = Buffer.concat([Buffer.from(m, 'ascii'), DISCOVERY_TAIL]);
      await new Promise<void>((r) => udp.send(pkt, 2430, '255.255.255.255', () => r()));
    }
    await sleep(25);
  }
}

const XHL_HEADER = Buffer.from(
  '4c49474854494e47534f46545f58484c' +
  '0000000000000000' +
  '14000000' +
  '01000000',
  'hex',
);

async function announceHardwareManager(
  udp24299: dgram.Socket,
  instanceId: Buffer,
): Promise<void> {
  const body114 = Buffer.alloc(114 - 32);
  instanceId.copy(body114, 0);
  body114.writeUInt32LE(crypto.randomBytes(4).readUInt32LE(0), 8);
  body114.writeUInt32LE(11, 12);
  body114.write('Hardware Manager\0', 18, 'ascii');
  const pkt114 = Buffer.concat([XHL_HEADER, body114]);
  await new Promise<void>((r) => udp24299.send(pkt114, 24299, '255.255.255.255', () => r()));
  await sleep(25);
  for (let i = 0; i < 2; i++) {
    const tail = Buffer.concat([crypto.randomBytes(4), Buffer.from([0x0a + i * 2, 0])]);
    const pkt46 = Buffer.concat([XHL_HEADER, instanceId, tail]);
    await new Promise<void>((r) => udp24299.send(pkt46, 24299, '255.255.255.255', () => r()));
    await sleep(25);
  }
}
import { deriveDmxKey, makeEphemeral, pointToWire, wireToPoint } from './kdf.js';
import { buildFrame } from './frame.js';

export interface SessionOpts {
  /** TCP/2431 control-channel target. */
  port?: number;
  /** Inter-message gap during handshake chatter (ms). Default 10. */
  chatterMs?: number;
  /** Settle after 0x2e enter-live before 0x10/0x11 (ms). Default 50. */
  settle2eMs?: number;
  /** Number of 0x70 sector reads (HWM-UI chatter). Default 0 = skip. */
  sectors?: number;
  /** Run HWM-style probe TCP connection before the live one. Default false. */
  runProbe?: boolean;
  /** Gap between probe close and go-live open (ms). Default 800. */
  probeGapMs?: number;
  /** Initial Token counter value. Default 0x80. */
  tokenStart?: number;
  /** Optional logger; default no-op. */
  log?: (...args: unknown[]) => void;
  /** Caller-owned UDP socket (bound to UDP_SRC_PORT 2430). When supplied,
   *  the session uses it for DMX sends + does NOT close it on destroy().
   *  Used by StickController to avoid the close-then-rebind cycle that
   *  empirically poisons the Stick into rejecting subsequent sessions
   *  inside a long-lived plugin process. */
  udp?: dgram.Socket;
}

const env = (k: string): string | undefined => process.env[k];
const envNum = (k: string, fallback: number): number =>
  env(k) != null ? Number(env(k)) : fallback;

export class StickSession {
  private constructor(
    public readonly ip: string,
    private sock: net.Socket,
    private udp: dgram.Socket,
    /** When true, we own the UDP socket and must close it on destroy(). */
    private ownsUdp: boolean,
    private key: Buffer,
    private token: Token,
    private rxBuf: Buffer,
  ) {}

  /** Open the TCP/2431 control channel, run the handshake (auth → pre-DMX
   *  chatter → ECDH → optional sector reads → go-live), and return a session
   *  ready for `send()`. */
  static async connect(ip: string, opts: SessionOpts = {}): Promise<StickSession> {
    const resolved = {
      port:        opts.port        ?? TCP_PORT,
      chatterMs:   opts.chatterMs   ?? envNum('CHATTER_MS', 10),
      settle2eMs:  opts.settle2eMs  ?? envNum('SETTLE_2E_MS', 50),
      sectors:     opts.sectors     ?? envNum('SECTORS', 0),
      runProbe:    opts.runProbe    ?? env('RUN_PROBE') === '1',
      probeGapMs:  opts.probeGapMs  ?? envNum('PROBE_GAP_MS', 800),
      tokenStart:  opts.tokenStart  ?? 0x80,
      log:         opts.log         ?? ((): void => undefined),
    };
    const log = resolved.log;
    const token = new Token(resolved.tokenStart);

    // UDP socket for the DMX stream + the HWM-faithful broadcasts. If the
    // caller (the controller, when running in a long-lived plugin process)
    // owns one, we reuse it; otherwise we create one for this session and
    // close it on destroy(). See the comment on SessionOpts.udp.
    let udp: dgram.Socket;
    let ownsUdp = false;
    if (opts.udp) {
      udp = opts.udp;
    } else {
      ownsUdp = true;
      udp = dgram.createSocket({ type: 'udp4', reuseAddr: true });
      await new Promise<void>((res, rej) => {
        udp.once('error', rej);
        udp.bind(UDP_SRC_PORT, () => { udp.setBroadcast(true); res(); });
      });
    }
    await discoveryBroadcast(udp);
    const udp24299 = dgram.createSocket('udp4');
    try {
      await new Promise<void>((res, rej) => {
        udp24299.once('error', rej);
        udp24299.bind(24299, () => { udp24299.setBroadcast(true); res(); });
      });
      const instanceId = crypto.randomBytes(8);
      await announceHardwareManager(udp24299, instanceId);
    } finally {
      udp24299.close();
    }
    await sleep(200);

    if (resolved.runProbe) {
      const probe = await openTcp(ip, resolved.port);
      try {
        const probeBuf = { v: Buffer.alloc(0) };
        probe.on('data', (d) => { probeBuf.v = Buffer.concat([probeBuf.v, d]); });
        await doAuth(probe, () => probeBuf.v, token, '[probe]', log);
        // 0x00 → 0xc9 status registration
        probe.write(msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')));
        await waitFor(() => findMsg(probeBuf.v, 0x00c9, 18), 1500);
        // 0x011c — we know this is just AES-encrypted device-info; discard reply
        probe.write(msg(MAGIC, 0x011c, token.next(), Buffer.from('01001600', 'hex')));
        await waitFor(() => findMsg(probeBuf.v, 0x011c, 22), 2000);
        // 0x007b — license query
        probe.write(msg(MAGIC, 0x007b, token.next()));
        await waitFor(() => findMsg(probeBuf.v, 0x007b, 22), 1500);
        await sleep(150);
      } finally {
        await new Promise<void>((res) => probe.end(() => res()));
      }
      await sleep(resolved.probeGapMs);
    }

    const sock = await openTcp(ip, resolved.port);
    const rxBuf = { v: Buffer.alloc(0) };
    sock.on('data', (d) => { rxBuf.v = Buffer.concat([rxBuf.v, d]); });

    await doAuth(sock, () => rxBuf.v, token, '[live]', log);

    // Pre-DMX chatter — match send_dmx.mjs EXACTLY (which is empirically
    // known to work multi-session from fresh processes). Earlier attempt
    // to wait explicitly for 0xc9 in the middle may have been wrong.
    for (const m of [
      msg(MAGIC, 0x46, Buffer.alloc(4)),
      msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
      msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
      msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')),
      msg(MAGIC, 0x011c, token.next(), Buffer.from('01001600', 'hex')),
      msg(MAGIC, 0x05, Buffer.from('0200', 'hex')),
    ]) {
      sock.write(m);
      await sleep(resolved.chatterMs);
    }
    if (findMsg(rxBuf.v, 0x00c9, 18)) log('0xc9 status received — session registered');

    // 0x10 — crypto-state query
    rxBuf.v = Buffer.alloc(0);
    sock.write(msg(MAGIC, 0x10, token.next()));
    const r10 = await waitFor(() => findMsg(rxBuf.v, 0x10, 22), 2000);
    if (r10) log(`0x10 crypto state: ${r10.readUInt32LE(0x12)}`);
    rxBuf.v = Buffer.alloc(0);

    // 0x0F — ECDH pubkey exchange
    const ecdh = makeEphemeral();
    const ourP256 = pointToWire(ecdh.getPublicKey(null, 'uncompressed') as Buffer);
    sock.write(msg(MAGIC, 0x0f, token.next(), ourP256));
    const r0f = await waitFor(() => findMsg(rxBuf.v, 0x0f, 86), 3000);
    let Qwire: Buffer = Q_FALLBACK;
    if (r0f != null) {
      Qwire = r0f.subarray(0x16, 0x56);
      log('0x0F ok — got Stick DMX pubkey');
    } else {
      log('0x0F — no reply, using static Stick key');
    }

    const key = deriveDmxKey(ecdh, wireToPoint(Qwire));
    log(`DMX key derived: ${key.toString('hex')}`);

    // 6b. device sync — replicated byte-for-byte against a captured HWM session
    sock.write(msg(MAGIC, 0x10, token.next())); await sleep(resolved.chatterMs);
    sock.write(msg(MAGIC, 0x75, token.next())); await sleep(resolved.chatterMs);
    sock.write(msg(MAGIC, 0x74, token.next())); await sleep(resolved.chatterMs);
    for (const p of ['0200000000', '0100000000', '0100000000', '02b37f0000']) {
      sock.write(msg(MAGIC, 0x71, token.next(), Buffer.from(p, 'hex')));
      await sleep(resolved.chatterMs);
    }

    // 0x70 sector reads — HWM commissioning-UI chatter; user-confirmed not
    // required for go-live. Default 0; set SECTORS=N or sectors:N to include.
    if (resolved.sectors > 0) {
      const full = [0];
      for (let s = 63; s <= 185; s++) full.push(s);
      const list = full.slice(0, resolved.sectors);
      log(`0x70 device download (${list.length} sectors)`);
      for (let i = 0; i < list.length; i++) {
        const body = Buffer.alloc(5);
        body.writeUInt32LE(list[i], 0);
        body[4] = 1;
        sock.write(msg(MAGIC, 0x70, token.next(), body));
        await sleep(12);
        if ((i & 0x1f) === 0x1f) rxBuf.v = Buffer.alloc(0);
      }
      await sleep(200);
    }
    rxBuf.v = Buffer.alloc(0);

    // Enter live mode: 0x2e, settle, 0x10/0x11/0x10
    sock.write(msg(MAGIC, 0x2e, Buffer.alloc(32))); await sleep(resolved.chatterMs);
    await sleep(resolved.settle2eMs);
    sock.write(msg(MAGIC, 0x10, token.next())); await sleep(resolved.chatterMs);
    sock.write(msg(MAGIC, 0x11, token.next()));
    const r11 = await waitFor(() => findMsg(rxBuf.v, 0x11, 22), 3000);
    log(r11 ? 'live mode enabled (0x11 ok)' : '0x11 — no reply');
    sock.write(msg(MAGIC, 0x10, token.next()));
    const r10b = await waitFor(() => findMsg(rxBuf.v, 0x10, 22), 1500);
    if (r10b) log(`0x10 after 0x11 — crypto state ${r10b.readUInt32LE(0x12)}`);

    return new StickSession(ip, sock, udp, ownsUdp, key, token, rxBuf.v);
  }

  /** Per-frame sequence counter (low byte). */
  private seqCtr = 0;

  /** Send one encrypted DMX frame for `universe` (port=0 for A).
   *  `channels` must be a 512-byte Uint8Array. */
  send(channels: Uint8Array, universe = 0): void {
    const frame = buildFrame({
      key: this.key,
      channels,
      port: universe,
      fieldA: this.token.next(),
      seq: this.seqCtr++,
    });
    this.udp.send(frame, UDP_DST_PORT, this.ip, () => {});
  }

  /** Dirty-close: UDP close + TCP RST. The Stick latches the last DMX values
   *  it received (cf. memory note `stick-actually-latches-on-clean-disconnect`).
   *  Idempotent. */
  destroy(): void {
    if (this.ownsUdp) {
      try { this.udp.close(); } catch { /* already closed */ }
    }
    try { this.sock.destroy(); } catch { /* already destroyed */ }
  }
}

// ── internals ──────────────────────────────────────────────────────────────

function openTcp(ip: string, port: number): Promise<net.Socket> {
  return new Promise((res, rej) => {
    const s = net.createConnection({ host: ip, port });
    s.setTimeout(5000);
    s.once('connect', () => { s.setTimeout(0); res(s); });
    s.once('error', rej);
    s.once('timeout', () => rej(new Error(`no response from ${ip}:${port}`)));
  });
}

async function doAuth(
  sock: net.Socket,
  getBuf: () => Buffer,
  token: Token,
  tag: string,
  log: (...a: unknown[]) => void,
): Promise<Buffer> {
  // 0x47 — LSAG_ALL hello; Stick replies with its 32-byte handshake key
  sock.write(msg(LSAG, 0x47, token.next()));
  const r47 = await waitFor(() => findMsg(getBuf(), 0x47, 54), 3000);
  let stickKey = Buffer.alloc(32);
  if (r47 != null) {
    stickKey = Buffer.from(r47.subarray(0x16, 0x36));
    log(`${tag} 0x47 ok`);
  } else {
    log(`${tag} 0x47 — no reply`);
  }

  // 0x48 — authenticated handshake (HMAC-SHA256 of the 82-byte head)
  const software = Buffer.alloc(32); software.write('software');
  const head48 = msg(LSAG, 0x48, token.next(), software, stickKey);
  const mac48 = crypto.createHmac('sha256', AUTH_KEY).update(head48).digest();
  sock.write(Buffer.concat([head48, mac48]));
  const r48 = await waitFor(() => findMsg(getBuf(), 0x48, 22), 2000);
  if (r48) {
    const st = r48.readUInt32LE(0x12);
    log(`${tag} 0x48 auth status: ${st}${st === 0 ? ' (ok)' : ' (REJECTED)'}`);
  } else {
    log(`${tag} 0x48 — no reply`);
  }
  return stickKey;
}
