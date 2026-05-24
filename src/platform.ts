// StickDe3Platform — Homebridge DynamicPlatformPlugin entry.
//
// Discovers fixtures from the loaded config, creates one Lightbulb accessory
// per patch entry, and owns the single shared StickController.

import type {
  API,
  Characteristic,
  DynamicPlatformPlugin,
  Logger,
  PlatformAccessory,
  PlatformConfig,
  Service,
} from 'homebridge';

import { LoadedConfig, loadConfig, RawConfig } from './config.js';
import { StickController } from './controller.js';
import { StickFixture } from './platformAccessory.js';
import { PLATFORM_NAME, PLUGIN_NAME } from './settings.js';

export class StickDe3Platform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service;
  public readonly Characteristic: typeof Characteristic;
  public readonly accessories: PlatformAccessory[] = [];

  private cfg: LoadedConfig | null = null;
  private controller: StickController | null = null;

  constructor(
    public readonly log: Logger,
    public readonly config: PlatformConfig,
    public readonly api: API,
  ) {
    this.Service = api.hap.Service;
    this.Characteristic = api.hap.Characteristic;

    try {
      this.cfg = loadConfig(
        config as unknown as RawConfig,
        api.user?.storagePath?.() ?? process.cwd(),
      );
    } catch (e) {
      this.log.error('config error:', (e as Error).message);
      return;
    }

    this.controller = new StickController(this.cfg.ip, this.log);
    this.log.info(
      `Stick-DE3 platform configured: ip=${this.cfg.ip}, ` +
      `${this.cfg.fixtures.length} fixture${this.cfg.fixtures.length === 1 ? '' : 's'}`,
    );

    this.api.on('didFinishLaunching', () => this.discoverDevices());
    this.api.on('shutdown', () => this.controller?.shutdown());
  }

  /** Called by Homebridge for each cached accessory at startup. We hold
   *  onto them in `this.accessories` and (re)wire them in `discoverDevices`. */
  configureAccessory(accessory: PlatformAccessory): void {
    this.log.debug(`restoring cached accessory: ${accessory.displayName}`);
    this.accessories.push(accessory);
  }

  private discoverDevices(): void {
    if (!this.cfg || !this.controller) return;

    const wantUuids = new Set<string>();
    for (const fx of this.cfg.fixtures) {
      const uuid = this.api.hap.uuid.generate(`stick-de3:${fx.id}`);
      wantUuids.add(uuid);

      const existing = this.accessories.find((a) => a.UUID === uuid);
      if (existing) {
        this.log.debug(`wiring cached accessory ${fx.id}`);
        existing.context.fixture = { id: fx.id }; // light marker; live ref kept in closure
        new StickFixture(this, existing, fx, this.controller);
      } else {
        this.log.info(`registering new accessory: ${fx.name} (${fx.id})`);
        const accessory = new this.api.platformAccessory(fx.name, uuid);
        accessory.context.fixture = { id: fx.id };
        new StickFixture(this, accessory, fx, this.controller);
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
        this.accessories.push(accessory);
      }
    }

    const stale = this.accessories.filter((a) => !wantUuids.has(a.UUID));
    if (stale.length) {
      this.log.info(`unregistering ${stale.length} stale accessor${stale.length === 1 ? 'y' : 'ies'}`);
      this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, stale);
      // drop them from our local list too
      for (const a of stale) {
        const i = this.accessories.indexOf(a);
        if (i >= 0) this.accessories.splice(i, 1);
      }
    }
  }
}
