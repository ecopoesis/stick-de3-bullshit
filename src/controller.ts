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
import { Buffer } from 'node:buffer';

import { Fixture } from './config.js';
import { HomeKitLightState } from './color/types.js';
import { StickSession } from './stick/session.js';
import { DEBOUNCE_MS, FRAME_INTERVAL_MS } from './settings.js';
import { sleep } from './stick/protocol.js';

export class StickController {
  private targets = new Map<number, Uint8Array>();
  private lastChangeAt = 0;
  private streaming = false;
  private currentSession: StickSession | null = null;

  constructor(
    private readonly ip: string,
    private readonly log: Logger,
    private readonly debounceMs: number = DEBOUNCE_MS,
    private readonly frameMs: number = FRAME_INTERVAL_MS,
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

  private async run(): Promise<void> {
    // Outer loop handles the race: a set arrives during teardown. We
    // re-open and resume rather than dropping the change.
    // eslint-disable-next-line no-constant-condition
    while (true) {
      let session: StickSession;
      try {
        session = await StickSession.connect(this.ip, {
          log: (msg, ...rest) => this.log.debug(String(msg), ...(rest as unknown[])),
        });
      } catch (e) {
        this.log.error('handshake failed:', (e as Error).message);
        return;
      }
      this.currentSession = session;
      this.log.info('Stick session ready');

      try {
        while (Date.now() - this.lastChangeAt < this.debounceMs) {
          for (const [u, arr] of this.targets) {
            session.send(arr, u);
          }
          await sleep(this.frameMs);
        }
      } finally {
        session.destroy();
        this.currentSession = null;
      }
      this.log.info('Stick session closed; values latched');

      if (Date.now() - this.lastChangeAt < this.debounceMs) {
        this.log.debug('change arrived during teardown — re-opening');
        continue;
      }
      return;
    }
  }

  /** Force-close any active session. For shutdown. */
  shutdown(): void {
    this.currentSession?.destroy();
    this.currentSession = null;
  }
}
