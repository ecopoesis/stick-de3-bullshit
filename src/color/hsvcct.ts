// hsvcct — the WAC DC-WD05 native model.
//
// 5 channels: intensity, intensity (fine), cct, saturation, hue. Saturation
// = 0  →  fixture is in CCT-only white mode (uses the cct channel).
// Saturation > 0  →  fixture is in color mode (uses hue + saturation).
//
// Mapping per CLAUDE.md (verified on hardware 2026-05-23):
//   On         → ch0 high byte / ch1 low byte = intensity
//   Brightness → ch0/ch1 16-bit
//   Hue        → ch4 = round(hue * 255 / 360)
//   Saturation → ch3 = round(sat * 2.55)
//   CCT        → ch2 = scale-to-Krange (K from 1000000/mireds)

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  brightness16,
  clamp,
  ctByte,
  requireRoles,
  writeMaybe16,
} from './types.js';

export const hsvcct: ColorModel = {
  id: 'hsvcct',
  characteristics: ['On', 'Brightness', 'Hue', 'Saturation', 'ColorTemperature'],
  validate(channels) {
    requireRoles(channels, ['intensity', 'cct', 'saturation', 'hue']);
    const c = channels.find((ch) => ch.role === 'cct');
    if (!c || c.kMin == null || c.kMax == null) {
      throw new Error("hsvcct model needs a Kelvin range, e.g. 'ColorTemp 1650-8000'");
    }
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const out = new Uint8Array(channels.length);
    let i = 0;
    while (i < channels.length) {
      const ch = channels[i];
      if (ch.fine) { i++; continue; }
      switch (ch.role) {
        case 'intensity':
          i = writeMaybe16(out, channels, i, brightness16(state));
          continue;
        case 'cct':
          out[i] = ctByte(state.colorTemperatureMireds, ch.kMin!, ch.kMax!);
          break;
        case 'saturation':
          out[i] = Math.round(clamp(state.saturation ?? 0, 0, 100) * 2.55);
          break;
        case 'hue':
          out[i] = Math.round((((state.hue ?? 0) % 360) / 360) * 255);
          break;
      }
      i++;
    }
    return out;
  },
};
