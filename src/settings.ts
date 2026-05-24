// Homebridge plugin constants.

export const PLATFORM_NAME = 'StickDe3';
export const PLUGIN_NAME = 'homebridge-dmx';

/** Coalesce HomeKit's multi-characteristic dispatch (Hue+Sat+Brightness
 *  arrive as 3 separate sets when picking a color). Mirrors unifi-ap-rgb. */
export const CHARACTERISTIC_UPDATE_DELAY_MS = 50;

/** Streaming "send until quiet" window. After the LAST HomeKit change, we
 *  keep streaming for this long, then dirty-disconnect → Stick latches.
 *  Empirical floor for the Stick's commit timer is ~500 ms; this leaves a
 *  comfortable margin. */
export const DEBOUNCE_MS = 750;

/** Frame interval (40ms = 25Hz, matches HWM exactly). */
export const FRAME_INTERVAL_MS = 40;
