// Color-model interfaces.
//
// A `ColorModel` translates the canonical HomeKit lightbulb state into the
// byte values a fixture expects, given that fixture's `channel_order` from
// the patch config. The optional `parse` is a placeholder for future
// state-read support; not implemented in v1.

export type HKCharacteristic =
  | 'On'
  | 'Brightness'
  | 'Hue'
  | 'Saturation'
  | 'ColorTemperature';

/** Canonical HomeKit state. Optional fields are populated only for models
 *  that expose the corresponding characteristic. */
export interface HomeKitLightState {
  on: boolean;
  brightness: number;              // 0..100 (percent)
  hue?: number;                    // 0..360 (degrees)
  saturation?: number;             // 0..100 (percent)
  colorTemperatureMireds?: number; // 50..400 (HomeKit mired range)
}

export type ChannelRole =
  | 'intensity'
  | 'cct'
  | 'saturation'
  | 'hue'
  | 'red'
  | 'green'
  | 'blue'
  | 'white'
  | 'warm-white'
  | 'cool-white'
  | 'amber';

/** One entry from a profile's `channel_order`. Produced by `parseChannelName`.
 *  `fine: true` means the byte at this slot is the low 8 bits of the 16-bit
 *  value paired with the immediately preceding non-fine entry of the same role. */
export interface ChannelDef {
  role: ChannelRole;
  fine?: boolean;
  /** For CCT channels: Kelvin range. Required for CCT to mireds<->byte mapping. */
  kMin?: number;
  kMax?: number;
}

export interface ColorModel {
  /** Lowercase identifier used in YAML/JSON config (`colormodel: hsvcct`). */
  readonly id: string;
  /** HomeKit characteristics this model wants on its fixture. */
  readonly characteristics: HKCharacteristic[];
  /** Throw if `channels` is inconsistent with this model's requirements. */
  validate(channels: ChannelDef[]): void;
  /** Produce a byte per `channels` entry, in order, given the HomeKit state. */
  render(state: HomeKitLightState, channels: ChannelDef[]): Uint8Array;
  /** Optional reverse direction; not implemented in v1. */
  parse?(bytes: Uint8Array, channels: ChannelDef[]): HomeKitLightState;
}

// ── shared helpers ─────────────────────────────────────────────────────────

/** Map HomeKit brightness (0..100) to a 16-bit value (0..65535) honoring On. */
export function brightness16(state: HomeKitLightState): number {
  if (!state.on) return 0;
  const pct = clamp(state.brightness, 0, 100);
  return Math.round((pct / 100) * 65535);
}

/** Map HomeKit brightness (0..100) to an 8-bit value (0..255) honoring On. */
export function brightness8(state: HomeKitLightState): number {
  if (!state.on) return 0;
  return Math.round((clamp(state.brightness, 0, 100) / 100) * 255);
}

/** Mireds → Kelvin → 0..255 byte across [kMin, kMax]. */
export function ctByte(mireds: number | undefined, kMin: number, kMax: number): number {
  if (mireds == null || mireds <= 0) return 128;
  const k = 1_000_000 / mireds;
  const t = (k - kMin) / (kMax - kMin);
  return Math.round(clamp(t, 0, 1) * 255);
}

/** HSV → RGB at V=1 (the brightness is applied separately on top — same idiom
 *  as unifi-ap-rgb so we don't double-darken). */
export function hsvToRgb01(hueDeg: number, satPct: number): { r: number; g: number; b: number } {
  const h = ((hueDeg % 360) + 360) % 360;
  const s = clamp(satPct, 0, 100) / 100;
  const c = s;                        // chroma when V = 1
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  let r1 = 0, g1 = 0, b1 = 0;
  if (h < 60)        [r1, g1, b1] = [c, x, 0];
  else if (h < 120)  [r1, g1, b1] = [x, c, 0];
  else if (h < 180)  [r1, g1, b1] = [0, c, x];
  else if (h < 240)  [r1, g1, b1] = [0, x, c];
  else if (h < 300)  [r1, g1, b1] = [x, 0, c];
  else               [r1, g1, b1] = [c, 0, x];
  const m = 1 - c;                    // V - c with V = 1
  return { r: r1 + m, g: g1 + m, b: b1 + m };
}

/** Scale 0..1 RGB by brightness (0..100) and on/off, return 0..255 bytes. */
export function rgbBytes(rgb01: { r: number; g: number; b: number }, state: HomeKitLightState):
  { r: number; g: number; b: number } {
  const m = state.on ? clamp(state.brightness, 0, 100) / 100 : 0;
  return {
    r: Math.round(rgb01.r * m * 255),
    g: Math.round(rgb01.g * m * 255),
    b: Math.round(rgb01.b * m * 255),
  };
}

export function clamp(v: number, lo: number, hi: number): number {
  return v < lo ? lo : v > hi ? hi : v;
}

/** Tag a single-byte channel index plus its fine companion (if any), and
 *  emit the right 16-bit split into `out`. Returns the index advanced past
 *  any fine companion. */
export function writeMaybe16(
  out: Uint8Array,
  channels: ChannelDef[],
  i: number,
  value16: number,
): number {
  const coarse = (value16 >> 8) & 0xff;
  const fine = value16 & 0xff;
  out[i] = coarse;
  if (channels[i + 1]?.fine && channels[i + 1].role === channels[i].role) {
    out[i + 1] = fine;
    return i + 2;
  }
  return i + 1;
}

/** Validate that `roles` is exactly the set of (coarse) roles in `channels`. */
export function requireRoles(channels: ChannelDef[], roles: ChannelRole[]): void {
  const present = channels.filter((c) => !c.fine).map((c) => c.role);
  for (const r of roles) {
    if (!present.includes(r)) {
      throw new Error(`channel_order missing required role '${r}'`);
    }
  }
  for (const r of present) {
    if (!roles.includes(r)) {
      throw new Error(`channel_order has unexpected role '${r}' for this model`);
    }
  }
}
