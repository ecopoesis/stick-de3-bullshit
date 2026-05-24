// Parsers — channel-name parser (used during config load) and CLI value
// parser (`#hex`, `hsl(...)`, `hwb(...)`, `0..255` for dimmer).

import { ChannelDef, ChannelRole, HomeKitLightState, clamp } from './types.js';

// ── channel-name parser ────────────────────────────────────────────────────

const NAME_TO_ROLE: Record<string, ChannelRole> = {
  intensity:   'intensity',
  brightness:  'intensity',
  dimmer:      'intensity',
  master:      'intensity',
  cct:         'cct',
  colortemp:   'cct',
  colortemperature: 'cct',
  temp:        'cct',
  tunable:     'cct',
  saturation:  'saturation',
  sat:         'saturation',
  hue:         'hue',
  red:         'red',
  r:           'red',
  green:       'green',
  g:           'green',
  blue:        'blue',
  b:           'blue',
  white:       'white',
  w:           'white',
  warmwhite:   'warm-white',
  ww:          'warm-white',
  coolwhite:   'cool-white',
  cw:          'cool-white',
  amber:       'amber',
  a:           'amber',
};

/** Parse a channel_order entry, e.g.:
 *    "Intensity"            → { role: 'intensity' }
 *    "Intensity (Fine)"     → { role: 'intensity', fine: true }
 *    "ColorTemp 1650-8000"  → { role: 'cct', kMin: 1650, kMax: 8000 }
 *    "Warm White"           → { role: 'warm-white' }
 */
export function parseChannelName(raw: string): ChannelDef {
  const s = raw.trim();
  // Strip a trailing (Fine) marker
  const fineMatch = /\((fine|lo|low)\)\s*$/i.exec(s);
  const beforeFine = fineMatch ? s.slice(0, fineMatch.index).trim() : s;
  // K range "Name <kMin>-<kMax>"
  const kMatch = /\s+(\d+)\s*[-–]\s*(\d+)\s*K?\s*$/.exec(beforeFine);
  const beforeK = kMatch ? beforeFine.slice(0, kMatch.index).trim() : beforeFine;
  // Normalize: strip whitespace, lowercase
  const key = beforeK.replace(/\s+/g, '').toLowerCase();
  const role = NAME_TO_ROLE[key];
  if (!role) throw new Error(`unknown channel name: "${raw}"`);

  const def: ChannelDef = { role };
  if (fineMatch) def.fine = true;
  if (kMatch) {
    const kMin = Number(kMatch[1]);
    const kMax = Number(kMatch[2]);
    if (!(kMin > 0 && kMax > kMin)) {
      throw new Error(`bad K range in "${raw}": expected positive ascending`);
    }
    def.kMin = kMin;
    def.kMax = kMax;
  }
  return def;
}

// ── CLI value parser ───────────────────────────────────────────────────────

/** Parse a CLI fixture value into a canonical HomeKit state.
 *  Supports:
 *    "#rrggbb" / "#rgb"   — hex color
 *    "rgb(r,g,b)"          — 0..255 each
 *    "hsl(h, s%, l%)"      — CSS HSL
 *    "hwb(h, w%, b%)"      — CSS HWB
 *    "kelvin(K)" / "K=K"   — CCT (sat=0, brightness=100)
 *    "0".."255"            — single byte (dimmer profile)
 *    "off" / "0%" / "on" / "100%"   — convenience
 */
export function parseValue(raw: string): HomeKitLightState {
  const s = raw.trim();

  // off / on
  if (/^off$/i.test(s))  return { on: false, brightness: 0 };
  if (/^on$/i.test(s))   return { on: true,  brightness: 100 };

  // bare number / percent — checked before hex because a 3-digit decimal
  // like "128" is ALSO a valid 3-char hex string.
  if (/^\d+%?$/.test(s)) {
    const isPct = s.endsWith('%');
    const v = Number(s.replace('%', ''));
    if (isPct) {
      return { on: v > 0, brightness: clamp(v, 0, 100) };
    }
    return { on: v > 0, brightness: Math.round((clamp(v, 0, 255) / 255) * 100) };
  }

  // hex (requires # for clarity unless it contains a non-decimal hex char)
  const hex = /^#?([0-9a-f]{3}|[0-9a-f]{6})$/i.exec(s);
  if (hex) {
    const h = hex[1];
    const expand = h.length === 3 ? [...h].map((c) => c + c).join('') : h;
    const r = parseInt(expand.slice(0, 2), 16);
    const g = parseInt(expand.slice(2, 4), 16);
    const b = parseInt(expand.slice(4, 6), 16);
    return rgbToState(r, g, b);
  }

  // rgb(r,g,b)
  const rgb = /^rgb\s*\(\s*([^)]+)\)$/i.exec(s);
  if (rgb) {
    const parts = splitArgs(rgb[1]);
    if (parts.length !== 3) throw new Error(`bad rgb(): need 3 args in "${raw}"`);
    const [r, g, b] = parts.map((p) => numberOrPercent(p, 255));
    return rgbToState(r, g, b);
  }

  // hsl(h, s%, l%)
  const hsl = /^hsl\s*\(\s*([^)]+)\)$/i.exec(s);
  if (hsl) {
    const parts = splitArgs(hsl[1]);
    if (parts.length !== 3) throw new Error(`bad hsl(): need 3 args in "${raw}"`);
    const h = angle(parts[0]);
    const sPct = percent(parts[1]);
    const lPct = percent(parts[2]);
    return hslToState(h, sPct, lPct);
  }

  // hwb(h, w%, b%)
  const hwb = /^hwb\s*\(\s*([^)]+)\)$/i.exec(s);
  if (hwb) {
    const parts = splitArgs(hwb[1]);
    if (parts.length !== 3) throw new Error(`bad hwb(): need 3 args in "${raw}"`);
    const h = angle(parts[0]);
    const wPct = percent(parts[1]);
    const bPct = percent(parts[2]);
    return hwbToState(h, wPct, bPct);
  }

  // kelvin
  const k = /^(?:k|kelvin)\s*[=:(]?\s*(\d+)\s*K?\)?$/i.exec(s);
  if (k) {
    const K = Number(k[1]);
    if (!(K > 0)) throw new Error(`bad kelvin in "${raw}"`);
    return { on: true, brightness: 100, saturation: 0, colorTemperatureMireds: Math.round(1_000_000 / K) };
  }

  throw new Error(`can't parse value: "${raw}"`);
}

function splitArgs(s: string): string[] {
  // Support both comma and space separators (CSS Level 4 syntax).
  return s.replace(/,/g, ' ').split(/\s+/).filter((p) => p.length > 0);
}

function percent(s: string): number {
  const m = /^(-?\d*\.?\d+)\s*%?$/.exec(s);
  if (!m) throw new Error(`bad percent: "${s}"`);
  return Number(m[1]);
}

function numberOrPercent(s: string, base: number): number {
  const m = /^(-?\d*\.?\d+)\s*(%?)$/.exec(s);
  if (!m) throw new Error(`bad number: "${s}"`);
  const v = Number(m[1]);
  return m[2] === '%' ? Math.round((v / 100) * base) : v;
}

function angle(s: string): number {
  const m = /^(-?\d*\.?\d+)\s*(deg|rad|turn)?$/i.exec(s);
  if (!m) throw new Error(`bad angle: "${s}"`);
  let v = Number(m[1]);
  if (/^rad$/i.test(m[2] ?? '')) v = (v * 180) / Math.PI;
  else if (/^turn$/i.test(m[2] ?? '')) v = v * 360;
  return ((v % 360) + 360) % 360;
}

/** Convert RGB (0..255) into HomeKit HSV+brightness state. */
function rgbToState(r: number, g: number, b: number): HomeKitLightState {
  const rN = clamp(r, 0, 255) / 255;
  const gN = clamp(g, 0, 255) / 255;
  const bN = clamp(b, 0, 255) / 255;
  const max = Math.max(rN, gN, bN);
  const min = Math.min(rN, gN, bN);
  const v = max;
  const d = max - min;
  let h = 0;
  if (d !== 0) {
    if (max === rN)      h = 60 * (((gN - bN) / d) % 6);
    else if (max === gN) h = 60 * (((bN - rN) / d) + 2);
    else                 h = 60 * (((rN - gN) / d) + 4);
  }
  if (h < 0) h += 360;
  const s = max === 0 ? 0 : (d / max) * 100;
  return {
    on: v > 0,
    brightness: Math.round(v * 100),
    hue: Math.round(h),
    saturation: Math.round(s),
  };
}

function hslToState(h: number, sPct: number, lPct: number): HomeKitLightState {
  // CSS HSL → HSV
  const s = clamp(sPct, 0, 100) / 100;
  const l = clamp(lPct, 0, 100) / 100;
  const v = l + s * Math.min(l, 1 - l);
  const sv = v === 0 ? 0 : 2 * (1 - l / v);
  return {
    on: v > 0,
    brightness: Math.round(v * 100),
    hue: ((h % 360) + 360) % 360,
    saturation: Math.round(sv * 100),
  };
}

function hwbToState(h: number, wPct: number, bPct: number): HomeKitLightState {
  // CSS HWB → HSV
  let w = clamp(wPct, 0, 100) / 100;
  let bk = clamp(bPct, 0, 100) / 100;
  if (w + bk > 1) { const t = w + bk; w /= t; bk /= t; }
  const v = 1 - bk;
  const s = v === 0 ? 0 : 1 - w / v;
  return {
    on: v > 0,
    brightness: Math.round(v * 100),
    hue: ((h % 360) + 360) % 360,
    saturation: Math.round(s * 100),
  };
}
