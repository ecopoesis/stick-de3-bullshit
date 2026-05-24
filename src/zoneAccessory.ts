// ZoneFixture — virtual HomeKit Lightbulb that dispatches to a set of
// member fixtures. Setting any characteristic of the zone updates the
// zone's local state, then calls controller.setFixture for each member
// using the zone's current state. The single controller debounce
// coalesces all member updates into one subprocess transaction.
//
// Per-member HomeKit accessories are NOT updated automatically. The user
// has accepted this trade-off: last command wins, and partial overrides
// of group commands are fine.

import type {
  CharacteristicValue,
  PlatformAccessory,
  Service,
} from 'homebridge';

import { Zone } from './config.js';
import { HKCharacteristic, HomeKitLightState } from './color/types.js';
import { StickController } from './controller.js';
import type { DmxPlatform } from './platform.js';
import { CHARACTERISTIC_UPDATE_DELAY_MS } from './settings.js';

export class ZoneFixture {
  private state: HomeKitLightState = { on: false, brightness: 100 };
  private pending: NodeJS.Timeout | null = null;

  constructor(
    private readonly platform: DmxPlatform,
    accessory: PlatformAccessory,
    private readonly zone: Zone,
    private readonly controllers: Map<string, StickController>,
  ) {
    const C = platform.Characteristic;
    const info = accessory.getService(platform.Service.AccessoryInformation);
    info?.setCharacteristic(C.Manufacturer, 'DMX')
        ?.setCharacteristic(C.Model, `Zone (${zone.members.length} fixtures)`)
        ?.setCharacteristic(C.SerialNumber, `zone-${zone.id}`);

    const bulb: Service =
      accessory.getService(platform.Service.Lightbulb)
      ?? accessory.addService(platform.Service.Lightbulb, zone.name);

    bulb.setCharacteristic(C.Name, zone.name);

    // Always expose On.
    bulb.getCharacteristic(C.On)
      .onGet(() => this.state.on)
      .onSet((v) => { this.state.on = Boolean(v); this.schedule(); });

    const has = (k: HKCharacteristic): boolean => zone.characteristics.includes(k);

    if (has('Brightness')) {
      bulb.getCharacteristic(C.Brightness)
        .onGet(() => this.state.brightness)
        .onSet((v: CharacteristicValue) => {
          this.state.brightness = Number(v);
          this.schedule();
        });
    }
    if (has('Hue')) {
      bulb.getCharacteristic(C.Hue)
        .onGet(() => this.state.hue ?? 0)
        .onSet((v) => { this.state.hue = Number(v); this.schedule(); });
    }
    if (has('Saturation')) {
      bulb.getCharacteristic(C.Saturation)
        .onGet(() => this.state.saturation ?? 0)
        .onSet((v) => { this.state.saturation = Number(v); this.schedule(); });
    }
    if (has('ColorTemperature')) {
      bulb.getCharacteristic(C.ColorTemperature)
        .onGet(() => this.state.colorTemperatureMireds ?? 200)
        .onSet((v) => {
          this.state.colorTemperatureMireds = Number(v);
          this.state.saturation = 0;
          this.schedule();
        });
    }
  }

  private schedule(): void {
    if (this.pending) clearTimeout(this.pending);
    this.pending = setTimeout(() => {
      this.pending = null;
      const s = this.state;
      this.platform.log.info(
        `[zone:${this.zone.id}] HK set: on=${s.on} br=${s.brightness}` +
        (s.hue != null ? ` h=${s.hue}` : '') +
        (s.saturation != null ? ` s=${s.saturation}` : '') +
        (s.colorTemperatureMireds != null ? ` ct=${s.colorTemperatureMireds}` : '') +
        ` → ${this.zone.members.length} members`,
      );
      // Dispatch the zone's state to each member via that member's controller.
      for (const m of this.zone.members) {
        const c = this.controllers.get(m.controller.id);
        if (!c) {
          this.platform.log.error(`zone "${this.zone.id}": no controller for "${m.id}"`);
          continue;
        }
        c.setFixture(m, this.state);
      }
    }, CHARACTERISTIC_UPDATE_DELAY_MS);
  }
}
