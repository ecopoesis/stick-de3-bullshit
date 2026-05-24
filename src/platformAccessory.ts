// StickFixture — one HomeKit Lightbulb accessory per patched fixture.

import type {
  CharacteristicValue,
  PlatformAccessory,
  Service,
} from 'homebridge';

import { Fixture } from './config.js';
import { HomeKitLightState } from './color/types.js';
import { StickController } from './controller.js';
import type { StickDe3Platform } from './platform.js';
import { CHARACTERISTIC_UPDATE_DELAY_MS } from './settings.js';

export class StickFixture {
  /** Current HomeKit state we'll send to the Stick on the next push. */
  private state: HomeKitLightState = { on: false, brightness: 100 };

  /** Debounce timer for HomeKit's multi-characteristic dispatch
   *  (Hue/Saturation/Brightness arrive as 3 separate set calls). */
  private pending: NodeJS.Timeout | null = null;

  constructor(
    private readonly platform: StickDe3Platform,
    private readonly accessory: PlatformAccessory,
    private readonly fixture: Fixture,
    private readonly controller: StickController,
  ) {
    const C = platform.Characteristic;
    const info = accessory.getService(platform.Service.AccessoryInformation);
    info?.setCharacteristic(C.Manufacturer, 'Stick-DE3 DMX')
        ?.setCharacteristic(C.Model, fixture.profile.name)
        ?.setCharacteristic(C.SerialNumber, fixture.id);

    const bulb: Service =
      accessory.getService(platform.Service.Lightbulb)
      ?? accessory.addService(platform.Service.Lightbulb, fixture.name);

    bulb.setCharacteristic(C.Name, fixture.name);

    const chars = fixture.profile.model.characteristics;

    bulb.getCharacteristic(C.On)
      .onGet(() => this.state.on)
      .onSet((v) => { this.state.on = Boolean(v); this.schedule(); });

    if (chars.includes('Brightness')) {
      bulb.getCharacteristic(C.Brightness)
        .onGet(() => this.state.brightness)
        .onSet((v: CharacteristicValue) => {
          this.state.brightness = Number(v);
          this.schedule();
        });
    }

    if (chars.includes('Hue')) {
      bulb.getCharacteristic(C.Hue)
        .onGet(() => this.state.hue ?? 0)
        .onSet((v) => {
          this.state.hue = Number(v);
          // setting hue implies color mode (sat>0); leave saturation as-is
          this.schedule();
        });
    }

    if (chars.includes('Saturation')) {
      bulb.getCharacteristic(C.Saturation)
        .onGet(() => this.state.saturation ?? 0)
        .onSet((v) => {
          this.state.saturation = Number(v);
          this.schedule();
        });
    }

    if (chars.includes('ColorTemperature')) {
      bulb.getCharacteristic(C.ColorTemperature)
        .onGet(() => this.state.colorTemperatureMireds ?? 200)
        .onSet((v) => {
          this.state.colorTemperatureMireds = Number(v);
          // CCT mode: HomeKit toggles between color and white modes; we mirror
          // by zeroing saturation when CCT is changed.
          this.state.saturation = 0;
          this.schedule();
        });
    }
  }

  private schedule(): void {
    if (this.pending) clearTimeout(this.pending);
    this.pending = setTimeout(() => {
      this.pending = null;
      this.controller.setFixture(this.fixture, this.state);
    }, CHARACTERISTIC_UPDATE_DELAY_MS);
  }
}
