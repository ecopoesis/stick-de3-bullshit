// Color-model registry. Look up a model by its lowercase id.

import { ColorModel } from './types.js';
import { dimmer } from './dimmer.js';
import { cct } from './cct.js';
import { rgb } from './rgb.js';
import { rgbw } from './rgbw.js';
import { rgbww } from './rgbww.js';
import { rgbaw } from './rgbaw.js';
import { hsvcct } from './hsvcct.js';

export const COLOR_MODELS: Record<string, ColorModel> = {
  dimmer: dimmer,
  cct:    cct,
  rgb:    rgb,
  rgbw:   rgbw,
  rgbww:  rgbww,
  rgbaw:  rgbaw,
  hsvcct: hsvcct,
};

/** Resolve a model by id (case-insensitive). Throws if unknown. */
export function getColorModel(id: string): ColorModel {
  const m = COLOR_MODELS[id.toLowerCase()];
  if (!m) {
    throw new Error(
      `unknown colormodel "${id}". Supported: ${Object.keys(COLOR_MODELS).join(', ')}`,
    );
  }
  return m;
}

export * from './types.js';
export * from './parsers.js';
