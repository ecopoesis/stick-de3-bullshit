// Homebridge plugin constants.

export const PLATFORM_NAME = 'DMX';
export const PLUGIN_NAME = '@ecopoesis/homebridge-dmx';

/** Coalesce HomeKit's multi-characteristic dispatch (Hue+Sat+Brightness
 *  arrive as 3 separate sets when picking a color). Mirrors unifi-ap-rgb. */
export const CHARACTERISTIC_UPDATE_DELAY_MS = 50;

/** "Send until quiet" debounce. After the LAST HomeKit change, we wait
 *  this long before spawning the send_dmx subprocess. Coalesces a fast
 *  slider drag into one transaction. */
export const DEBOUNCE_MS = 750;

/** Frame interval (40ms = 25Hz, matches HWM exactly). Unused by the
 *  subprocess controller — send_dmx.mjs's own FRAME_HZ env knob is what
 *  matters now. */
export const FRAME_INTERVAL_MS = 40;
