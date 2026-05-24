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
}

const env = (k: string): string | undefined => process.env[k];
const envNum = (k: string, fallback: number): number =>
  env(k) != null ? Number(env(k)) : fallback;

export class StickSession {
  private constructor(
    public readonly ip: string,
    private sock: net.Socket,
    private udp: dgram.Socket,
    private key: Buffer,
    private token: Token,
    private rxBuf: Buffer,
    public readonly opts: Required<Omit<SessionOpts, 'log'>> & { log: (...a: unknown[]) => void },
  ) {}

  /** Open the TCP/2431 control channel, run the handshake (auth → pre-DMX
   *  chatter → ECDH → optional sector reads → go-live), and return a session
   *  ready for `send()`. */
  static async connect(ip: string, opts: SessionOpts = {}): Promise<StickSession> {
    const resolved: Required<Omit<SessionOpts, 'log'>> & { log: (...a: unknown[]) => void } = {
      port:        opts.port        ?? TCP_PORT,
      chatterMs:   opts.chatterMs   ?? envNum('CHATTER_MS', 10),
      settle2eMs:  opts.settle2eMs  ?? envNum('SETTLE_2E_MS', 50),
      sectors:     opts.sectors     ?? envNum('SECTORS', 0),
      runProbe:    opts.runProbe    ?? env('RUN_PROBE') === '1',
      probeGapMs:  opts.probeGapMs  ?? envNum('PROBE_GAP_MS', 800),
      tokenStart:  opts.tokenStart  ?? 0x80,
      log:         opts.log         ?? (() => {}),
    };
    const log = resolved.log;
    const token = new Token(resolved.tokenStart);

    // UDP socket for the DMX stream + (silently) discovery, though we no
    // longer broadcast (Stick is reached by static IP).
    const udp = dgram.createSocket('udp4');
    await new Promise<void>((res, rej) => {
      udp.once('error', rej);
      udp.bind(UDP_SRC_PORT, () => { udp.setBroadcast(true); res(); });
    });

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

    // Pre-DMX chatter — sent ONE AT A TIME with a small gap. We split the
    // sequence into TWO groups around the 0x00 → 0xc9 round-trip so we can
    // wait explicitly for 0xc9. Without the explicit wait, a cold-start
    // Stick that takes >chatterMs to reply causes 0xc9 to land AFTER we've
    // already cleared rxBuf, the session is silently un-registered, and
    // the rest of the handshake "succeeds" but go-live never grants. We saw
    // this 1-in-N cold-start: subsequent runs were fine because the Stick
    // had warmed up, but the first run after idle would not latch.
    for (const m of [
      msg(MAGIC, 0x46, Buffer.alloc(4)),
      msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
      msg(MAGIC, 0x09, Buffer.from('14000000', 'hex')),
    ]) {
      sock.write(m);
      await sleep(resolved.chatterMs);
    }
    sock.write(msg(MAGIC, 0x00, Buffer.from('14000000', 'hex')));
    const c9 = await waitFor(() => findMsg(rxBuf.v, 0x00c9, 18), 2000);
    if (c9) {
      log('0xc9 status received — session registered');
    } else {
      log('0xc9 NOT received within 2s — Stick may not be registered');
    }
    for (const m of [
      msg(MAGIC, 0x011c, token.next(), Buffer.from('01001600', 'hex')),
      msg(MAGIC, 0x05, Buffer.from('0200', 'hex')),
    ]) {
      sock.write(m);
      await sleep(resolved.chatterMs);
    }

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

    return new StickSession(ip, sock, udp, key, token, rxBuf.v, resolved);
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
    try { this.udp.close(); } catch { /* already closed */ }
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
