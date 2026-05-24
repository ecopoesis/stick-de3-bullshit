#!/usr/bin/env node
// stick — set DMX channels on a Stick-DE3, transactionally.
//
//   stick [--config <yaml>] <ip> <assignment> [<assignment>...]
//
// Assignment forms:
//   <fixture-id>=<value>            named fixture from config
//                                   value: "#FFFFFF", "hsl(120,50%,50%)",
//                                          "hwb(180 10% 20%)", "rgb(255,128,0)",
//                                          "kelvin(2700)", "50%", "128", "on", "off"
//   u<universe>,<channel>=<byte>    raw single-channel write (e.g. "uA,6=255")
//
// Env knobs (same as the StickSession opts):
//   STREAM_MS, CHATTER_MS, SETTLE_2E_MS, FRAME_HZ, SECTORS, RUN_PROBE,
//   PROBE_GAP_MS, KEY_DUMP
//
// Config search order if --config not given:
//   $STICK_CONFIG, ./stick-de3.yaml, ~/.config/stick-de3.yaml.
// A config is OPTIONAL when ONLY raw u<universe>,<channel>=<byte> assignments
// are used (and the ip is on the command line).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { Buffer } from 'node:buffer';

import { LoadedConfig, loadConfig } from '../config.js';
import { parseValue } from '../color/parsers.js';
import { StickSession } from '../stick/session.js';

interface CliAssignment {
  /** universe 0/1 */
  universe: number;
  /** 1-based channel */
  channel: number;
  /** byte value */
  value: number;
}

function findDefaultConfig(): string | null {
  const candidates = [
    process.env.STICK_CONFIG,
    path.resolve(process.cwd(), 'stick-de3.yaml'),
    path.resolve(os.homedir(), '.config/stick-de3.yaml'),
  ].filter(Boolean) as string[];
  for (const c of candidates) {
    try { fs.accessSync(c, fs.constants.R_OK); return c; } catch { /* miss */ }
  }
  return null;
}

function usage(): never {
  console.error(
    'usage: stick [--config <yaml>] <ip> <assignment> [<assignment>...]\n' +
    '  assignments:\n' +
    '    <fixture-id>=<value>        named fixture (config required)\n' +
    '    u<universe>,<channel>=<n>   raw, e.g. uA,6=255',
  );
  process.exit(1);
}

function parseArgs(argv: string[]): { configPath: string | null; ip: string; assigns: string[] } {
  let configPath: string | null = null;
  const rest: string[] = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--config' || argv[i] === '-c') {
      configPath = argv[++i];
    } else if (argv[i] === '-h' || argv[i] === '--help') {
      usage();
    } else {
      rest.push(argv[i]);
    }
  }
  if (rest.length < 2) usage();
  return { configPath, ip: rest[0], assigns: rest.slice(1) };
}

function loadOptionalConfig(configPath: string | null, ip: string): LoadedConfig | null {
  const p = configPath ?? findDefaultConfig();
  if (!p) return null;
  const cwd = path.dirname(p);
  if (p.endsWith('.yaml') || p.endsWith('.yml')) {
    return loadConfig({ ip, yamlPath: p }, cwd);
  }
  const json = JSON.parse(fs.readFileSync(p, 'utf8'));
  if (!json.ip) json.ip = ip;
  return loadConfig(json, cwd);
}

// Build a Map<universe, Uint8Array(512)> of channel targets from CLI args.
function resolveAssignments(
  assigns: string[],
  cfg: LoadedConfig | null,
): Map<number, Uint8Array> {
  const universes = new Map<number, Uint8Array>();
  const slot = (u: number) => {
    let arr = universes.get(u);
    if (!arr) { arr = new Uint8Array(512); universes.set(u, arr); }
    return arr;
  };

  for (const a of assigns) {
    const eq = a.indexOf('=');
    if (eq < 0) throw new Error(`bad assignment "${a}": expected key=value`);
    const lhs = a.slice(0, eq).trim();
    const rhs = a.slice(eq + 1).trim();

    // Raw: u<universe>,<channel>=<byte>
    const raw = /^u([ab]),(\d+)$/i.exec(lhs);
    if (raw) {
      const u = raw[1].toUpperCase() === 'A' ? 0 : 1;
      const ch = Number(raw[2]);
      const byte = Number(rhs);
      if (!Number.isInteger(ch) || ch < 1 || ch > 512) {
        throw new Error(`raw "${a}": channel out of 1..512`);
      }
      if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
        throw new Error(`raw "${a}": value out of 0..255`);
      }
      slot(u)[ch - 1] = byte;
      continue;
    }

    // Named fixture
    if (!cfg) {
      throw new Error(`assignment "${a}" needs a config; use --config or set STICK_CONFIG`);
    }
    const fx = cfg.fixtures.find((f) => f.id === lhs);
    if (!fx) {
      throw new Error(`unknown fixture id "${lhs}". Known: ${cfg.fixtures.map((f) => f.id).join(', ')}`);
    }
    const state = parseValue(rhs);
    const bytes = fx.profile.model.render(state, fx.profile.channels);
    const arr = slot(fx.universe);
    for (let i = 0; i < bytes.length; i++) {
      arr[fx.startCh - 1 + i] = bytes[i];
    }
  }

  return universes;
}

async function main(): Promise<void> {
  const { configPath, ip, assigns } = parseArgs(process.argv.slice(2));
  const cfg = loadOptionalConfig(configPath, ip);
  // CLI ip arg overrides config ip if both present
  const target = ip;

  const universes = resolveAssignments(assigns, cfg);
  if (universes.size === 0) {
    console.error('no channels to set'); process.exit(1);
  }

  // Summarise what we're sending
  for (const [u, arr] of universes) {
    const lit = [...arr.entries()].filter(([, v]) => v).map(([i, v]) => `ch${i + 1}=${v}`);
    console.log(`  universe ${u ? 'B' : 'A'}: ${lit.length} channel${lit.length === 1 ? '' : 's'}: ${lit.join(' ')}`);
  }

  const session = await StickSession.connect(target, {
    log: (...a) => console.log('  ', ...a),
  });

  // Optional key dump (for offline pcap decryption)
  try {
    const keyPath = process.env.KEY_DUMP || `${os.homedir()}/.send_dmx-key.txt`;
    // Access the key indirectly: it's a private field of StickSession, so we
    // dump the most recent value we know about. Since we don't expose it,
    // skip the dump here — the diagnostic tools in tools/ already do this.
    void keyPath;
  } catch { /* silent */ }

  const STREAM_MS = Number(process.env.STREAM_MS || 750);
  const FRAME_HZ = Number(process.env.FRAME_HZ || 25);
  const frameMs = Math.max(1, Math.round(1000 / FRAME_HZ));

  console.log(`  streaming at ${FRAME_HZ} Hz (${frameMs}ms) for ${STREAM_MS}ms`);
  let nFrames = 0;
  const timer = setInterval(() => {
    for (const [u, arr] of universes) {
      session.send(arr, u);
      nFrames++;
    }
  }, frameMs);

  await new Promise((res) => setTimeout(res, STREAM_MS));
  clearInterval(timer);
  console.log(`  streamed ${nFrames} frames`);

  session.destroy();
  console.log('  disconnected (RST) — Stick should hold the last value');
}

main().catch((e) => { console.error('failed:', e); process.exit(1); });
