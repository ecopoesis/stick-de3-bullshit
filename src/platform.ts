// DmxPlatform — Homebridge DynamicPlatformPlugin entry.
//
// Loads the config, instantiates one StickController per controller spec,
// creates one Lightbulb accessory per patch entry, wires each accessory to
// its controller.

import type {
  API,
  Characteristic,
  DynamicPlatformPlugin,
  Logger,
  PlatformAccessory,
  PlatformConfig,
  Service,
} from 'homebridge';

import { Controller, LoadedConfig, loadConfig, RawConfig } from './config.js';
import { StickController } from './controller.js';
import { StickFixture } from './platformAccessory.js';
import { ZoneFixture } from './zoneAccessory.js';
import { PLATFORM_NAME, PLUGIN_NAME } from './settings.js';

export class DmxPlatform implements DynamicPlatformPlugin {
  public readonly Service: typeof Service;
  public readonly Characteristic: typeof Characteristic;
  public readonly accessories: PlatformAccessory[] = [];

  private cfg: LoadedConfig | null = null;
  private controllers = new Map<string, StickController>();

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

    for (const c of this.cfg.controllers) {
      this.controllers.set(c.id, this.makeController(c));
    }

    this.log.info(
      `DMX platform configured: ${this.cfg.controllers.length} controller` +
      `${this.cfg.controllers.length === 1 ? '' : 's'}, ` +
      `${this.cfg.fixtures.length} fixture${this.cfg.fixtures.length === 1 ? '' : 's'}, ` +
      `${this.cfg.zones.length} zone${this.cfg.zones.length === 1 ? '' : 's'}`,
    );

    this.api.on('didFinishLaunching', () => this.discoverDevices());
    this.api.on('shutdown', () => {
      for (const c of this.controllers.values()) c.shutdown();
    });
  }

  private makeController(c: Controller): StickController {
    switch (c.type) {
      case 'StickDE3':
        return new StickController(c.ip, this.log);
      default:
        throw new Error(`unsupported controller type "${(c as Controller).type}"`);
    }
  }

  /** Called by Homebridge for each cached accessory at startup. */
  configureAccessory(accessory: PlatformAccessory): void {
    this.log.debug(`restoring cached accessory: ${accessory.displayName}`);
    this.accessories.push(accessory);
  }

  private discoverDevices(): void {
    if (!this.cfg) return;

    const wantUuids = new Set<string>();
    for (const fx of this.cfg.fixtures) {
      const uuid = this.api.hap.uuid.generate(`dmx:${fx.controller.id}:${fx.id}`);
      wantUuids.add(uuid);

      const controller = this.controllers.get(fx.controller.id);
      if (!controller) {
        this.log.error(`fixture "${fx.id}": no controller "${fx.controller.id}"`);
        continue;
      }

      const existing = this.accessories.find((a) => a.UUID === uuid);
      if (existing) {
        this.log.debug(`wiring cached accessory ${fx.id}`);
        existing.context.fixture = { id: fx.id, controllerId: fx.controller.id };
        new StickFixture(this, existing, fx, controller);
      } else {
        this.log.info(`registering new accessory: ${fx.name} (${fx.id})`);
        const accessory = new this.api.platformAccessory(fx.name, uuid);
        accessory.context.fixture = { id: fx.id, controllerId: fx.controller.id };
        new StickFixture(this, accessory, fx, controller);
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
        this.accessories.push(accessory);
      }
    }

    // Zones — virtual accessories that dispatch to their member fixtures.
    for (const zone of this.cfg.zones) {
      const uuid = this.api.hap.uuid.generate(`dmx-zone:${zone.id}`);
      wantUuids.add(uuid);
      const existing = this.accessories.find((a) => a.UUID === uuid);
      if (existing) {
        this.log.debug(`wiring cached zone ${zone.id}`);
        existing.context.zone = { id: zone.id };
        new ZoneFixture(this, existing, zone, this.controllers);
      } else {
        this.log.info(`registering new zone: ${zone.name} (${zone.id}, ${zone.members.length} members)`);
        const accessory = new this.api.platformAccessory(zone.name, uuid);
        accessory.context.zone = { id: zone.id };
        new ZoneFixture(this, accessory, zone, this.controllers);
        this.api.registerPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, [accessory]);
        this.accessories.push(accessory);
      }
    }

    const stale = this.accessories.filter((a) => !wantUuids.has(a.UUID));
    if (stale.length) {
      this.log.info(`unregistering ${stale.length} stale accessor${stale.length === 1 ? 'y' : 'ies'}`);
      this.api.unregisterPlatformAccessories(PLUGIN_NAME, PLATFORM_NAME, stale);
      for (const a of stale) {
        const i = this.accessories.indexOf(a);
        if (i >= 0) this.accessories.splice(i, 1);
      }
    }
  }
}
