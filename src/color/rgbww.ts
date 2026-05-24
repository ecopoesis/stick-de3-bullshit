// rgbww — RGB + WarmWhite + CoolWhite. The extracted white component
// is split between WW and CW based on the HomeKit CCT (mireds), falling
// back to 50/50 when CCT isn't set. WW channel optionally declares K=K
// (e.g. "WarmWhite 2700") and CW does the same; if absent, defaults
// 2700K (WW) / 6500K (CW) are used.

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  clamp,
  hsvToRgb01,
  rgbBytes,
  requireRoles,
} from './types.js';

const DEFAULT_WW_K = 2700;
const DEFAULT_CW_K = 6500;

export const rgbww: ColorModel = {
  id: 'rgbww',
  characteristics: ['On', 'Brightness', 'Hue', 'Saturation', 'ColorTemperature'],
  validate(channels) {
    requireRoles(channels, ['red', 'green', 'blue', 'warm-white', 'cool-white']);
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const wwK = channels.find((c) => c.role === 'warm-white')?.kMin ?? DEFAULT_WW_K;
    const cwK = channels.find((c) => c.role === 'cool-white')?.kMin ?? DEFAULT_CW_K;

    const rgb01 = hsvToRgb01(state.hue ?? 0, state.saturation ?? 0);
    const px = rgbBytes(rgb01, state);
    const w = Math.min(px.r, px.g, px.b);

    // Mix ratio: when CCT is at WW endpoint -> all WW; at CW endpoint -> all CW.
    let warmFrac = 0.5;
    if (state.colorTemperatureMireds != null && state.colorTemperatureMireds > 0) {
      const k = 1_000_000 / state.colorTemperatureMireds;
      warmFrac = clamp((cwK - k) / (cwK - wwK), 0, 1);
    }
    const ww = Math.round(w * warmFrac);
    const cw = w - ww;

    const out = new Uint8Array(channels.length);
    for (let i = 0; i < channels.length; i++) {
      if (channels[i].fine) continue;
      switch (channels[i].role) {
        case 'red':         out[i] = px.r - w; break;
        case 'green':       out[i] = px.g - w; break;
        case 'blue':        out[i] = px.b - w; break;
        case 'warm-white':  out[i] = ww; break;
        case 'cool-white':  out[i] = cw; break;
      }
    }
    return out;
  },
};
