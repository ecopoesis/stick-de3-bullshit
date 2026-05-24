// StickController — single shared session manager for the platform.
//
// Behavior:
//   - HomeKit calls setFixture(fixture, state) any number of times
//   - The first call opens a StickSession and starts streaming at 25 Hz
//   - Subsequent calls within DEBOUNCE_MS just update the targets and
//     extend the streaming window
//   - When DEBOUNCE_MS passes with no new calls, RST the session → latch
//   - If a call arrives during teardown, immediately re-open and continue

import type { Logger } from 'homebridge';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import { Fixture } from './config.js';
import { HomeKitLightState } from './color/types.js';
import { DEBOUNCE_MS } from './settings.js';
import { sleep } from './stick/protocol.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
// dist/controller.js → ../tools/send_dmx.mjs
const SEND_DMX_PATH = path.resolve(__dirname, '..', 'tools', 'send_dmx.mjs');

export class StickController {
  private targets = new Map<number, Uint8Array>();
  private lastChangeAt = 0;
  private streaming = false;
  /** Tracks whether the very first subprocess in this controller's
   *  lifetime should set RUN_PROBE=1. After a Stick power-cycle (which
   *  we can't detect in-band) the probe is required to (re-)register
   *  the client. Subsequent subprocesses can skip it. */
  private needsProbe = true;

  constructor(
    private readonly ip: string,
    private readonly log: Logger,
    private readonly debounceMs: number = DEBOUNCE_MS,
  ) {}

  /** Stage a fixture's bytes into the universe target buffer and ensure
   *  the streaming loop is running. */
  setFixture(fixture: Fixture, state: HomeKitLightState): void {
    const arr = this.universeBuf(fixture.universe);
    const bytes = fixture.profile.model.render(state, fixture.profile.channels);
    for (let i = 0; i < bytes.length; i++) {
      arr[fixture.startCh - 1 + i] = bytes[i];
    }
    this.lastChangeAt = Date.now();
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
    this.log.info(`setFixture ${fixture.id}@DMX${fixture.startCh}=${hex} streaming=${this.streaming}`);
    if (!this.streaming) {
      this.streaming = true;
      this.run().catch((e) => {
        this.log.error('streaming loop crashed:', (e as Error).message);
      }).finally(() => {
        this.streaming = false;
      });
    }
  }

  private universeBuf(u: number): Uint8Array {
    let arr = this.targets.get(u);
    if (!arr) { arr = new Uint8Array(512); this.targets.set(u, arr); }
    return arr;
  }

  /** Build the CLI args from current targets. Only non-zero channels are
   *  passed — send_dmx initialises the universe to 0 so omission == 0. */
  private buildArgs(): string[] {
    const args: string[] = [SEND_DMX_PATH, this.ip];
    for (const [u, arr] of this.targets) {
      for (let i = 0; i < 512; i++) {
        if (arr[i] !== 0) args.push(`${u},${i + 1}=${arr[i]}`);
      }
    }
    return args;
  }

  /** Subprocess approach: spawn tools/send_dmx.mjs for each transaction.
   *  Fresh node process = no in-process state poisoning that breaks
   *  session 2+ in the long-lived plugin. Costs ~1.5-3s per spawn (process
   *  startup + handshake + 750ms stream + RST) but is empirically reliable. */
  private async run(): Promise<void> {
    // eslint-disable-next-line no-constant-condition
    while (true) {
      // Wait for the debounce window to clear (no changes for debounceMs).
      while (Date.now() - this.lastChangeAt < this.debounceMs) {
        await sleep(50);
      }

      const runProbe = this.needsProbe;
      const args = this.buildArgs();
      const env = {
        ...process.env,
        STREAM_MS: '750',
        SECTORS: '0',
        ...(runProbe ? { RUN_PROBE: '1' } : {}),
      };
      this.log.info(`send_dmx subprocess: ${args.length - 2} channels` +
                    (runProbe ? ' (with probe)' : ''));

      const startedAt = Date.now();
      let stderr = '';
      const child = spawn('node', args, { env });
      child.stdout.on('data', (d) => this.log.debug(`[send_dmx] ${d.toString().trimEnd()}`));
      child.stderr.on('data', (d) => { stderr += d.toString(); });

      const exitCode = await new Promise<number>((res) => {
        child.on('exit', (code) => res(code ?? -1));
        child.on('error', (e) => {
          this.log.error('send_dmx spawn error:', e.message);
          res(-1);
        });
      });
      const elapsedMs = Date.now() - startedAt;

      if (exitCode === 0) {
        this.needsProbe = false;
        this.log.info(`send_dmx done in ${elapsedMs}ms`);
      } else {
        this.log.error(`send_dmx exited ${exitCode} after ${elapsedMs}ms; stderr: ${stderr.slice(0, 200)}`);
      }

      // If a change arrived during the subprocess, run another transaction.
      if (Date.now() - this.lastChangeAt < this.debounceMs) continue;
      return;
    }
  }

  /** Shutdown hook. Subprocess approach has no long-lived state. */
  shutdown(): void {
    /* no-op */
  }
}
