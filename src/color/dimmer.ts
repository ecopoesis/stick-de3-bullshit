// dimmer — single-channel intensity-only fixture.
// channel_order: 1 entry, role 'intensity' (optionally followed by a 'fine').

import {
  ChannelDef,
  ColorModel,
  HomeKitLightState,
  brightness16,
  requireRoles,
  writeMaybe16,
} from './types.js';

export const dimmer: ColorModel = {
  id: 'dimmer',
  characteristics: ['On', 'Brightness'],
  validate(channels) {
    requireRoles(channels, ['intensity']);
  },
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array {
    const out = new Uint8Array(channels.length);
    writeMaybe16(out, channels, 0, brightness16(state));
    return out;
  },
};
