// cct — tunable-white (2 channel): intensity + color temp. No color.
// channel_order: intensity (+optional fine) and a cct channel with K range.

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  brightness16,
  ctByte,
  requireRoles,
  writeMaybe16,
} from './types.js';

export const cct: ColorModel = {
  id: 'cct',
  characteristics: ['On', 'Brightness', 'ColorTemperature'],
  validate(channels) {
    requireRoles(channels, ['intensity', 'cct']);
    const c = channels.find((ch) => ch.role === 'cct');
    if (!c || c.kMin == null || c.kMax == null) {
      throw new Error("cct model needs a Kelvin range, e.g. 'ColorTemp 2700-6500'");
    }
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const out = new Uint8Array(channels.length);
    let i = 0;
    while (i < channels.length) {
      const ch = channels[i];
      if (ch.role === 'intensity' && !ch.fine) {
        i = writeMaybe16(out, channels, i, brightness16(state));
      } else if (ch.role === 'cct' && !ch.fine) {
        out[i] = ctByte(state.colorTemperatureMireds, ch.kMin!, ch.kMax!);
        i++;
      } else {
        i++;
      }
    }
    return out;
  },
};
