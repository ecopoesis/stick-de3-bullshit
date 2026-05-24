// rgbaw — RGB + Amber + White. Amber gets pulled out of the
// yellow/orange region of the RGB, white from the remaining
// achromatic component. Stage-lighting common.

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  hsvToRgb01,
  rgbBytes,
  requireRoles,
} from './types.js';

export const rgbaw: ColorModel = {
  id: 'rgbaw',
  characteristics: ['On', 'Brightness', 'Hue', 'Saturation'],
  validate(channels) {
    requireRoles(channels, ['red', 'green', 'blue', 'amber', 'white']);
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const rgb01 = hsvToRgb01(state.hue ?? 0, state.saturation ?? 0);
    const px = rgbBytes(rgb01, state);

    // Amber ≈ min(R, ~0.75·G) where G is dominated by R, ie. yellow-orange region.
    // Pull amber out of the green to avoid red dimming.
    const amber = Math.min(px.r, Math.round(px.g * 0.75));
    let r = px.r, g = px.g - amber, b = px.b;

    // White from the remaining achromatic component.
    const w = Math.min(r, g, b);
    r -= w; g -= w; b -= w;

    const out = new Uint8Array(channels.length);
    for (let i = 0; i < channels.length; i++) {
      if (channels[i].fine) continue;
      switch (channels[i].role) {
        case 'red':   out[i] = r; break;
        case 'green': out[i] = g; break;
        case 'blue':  out[i] = b; break;
        case 'amber': out[i] = amber; break;
        case 'white': out[i] = w; break;
      }
    }
    return out;
  },
};
