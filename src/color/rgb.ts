// rgb — 3-channel additive color.
// channel_order: red, green, blue (any order).

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  hsvToRgb01,
  rgbBytes,
  requireRoles,
} from './types.js';

export const rgb: ColorModel = {
  id: 'rgb',
  characteristics: ['On', 'Brightness', 'Hue', 'Saturation'],
  validate(channels) {
    requireRoles(channels, ['red', 'green', 'blue']);
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const rgb01 = hsvToRgb01(state.hue ?? 0, state.saturation ?? 0);
    const px = rgbBytes(rgb01, state);
    const out = new Uint8Array(channels.length);
    for (let i = 0; i < channels.length; i++) {
      if (channels[i].fine) continue; // RGB fine channels not common; leave zero
      switch (channels[i].role) {
        case 'red':   out[i] = px.r; break;
        case 'green': out[i] = px.g; break;
        case 'blue':  out[i] = px.b; break;
      }
    }
    return out;
  },
};
