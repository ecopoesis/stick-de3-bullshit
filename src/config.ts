// Config loader + validator.
//
// Inputs:
//   - Homebridge config: `platforms[].StickDe3` block from Homebridge's
//     config.json. Required top-level field `ip`. Optional `yamlPath` points
//     to an external YAML file whose contents take precedence over the JSON.
//   - YAML override: same shape as the JSON block.
//
// Output: a normalized `LoadedConfig` the platform consumes. Validates:
//   - profiles: each `colormodel` is recognised, channel_order parses cleanly
//     and is consistent with the model's requirements
//   - patch: unique ids, valid universe ∈ {A, B}, start ∈ [1, 512-nch+1],
//     non-overlapping DMX ranges within a universe

import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

import { ChannelDef, ColorModel } from './color/types.js';
import { getColorModel } from './color/index.js';
import { parseChannelName } from './color/parsers.js';

export interface ProfileSpec {
  name: string;
  colormodel: string;
  channel_order: string[];
}

export interface PatchSpec {
  id: string;            // unique handle (kebab-case)
  name: string;          // human-friendly HomeKit name
  type: string;          // profile name (refers to a ProfileSpec.name)
  universe?: string;     // 'A' or 'B'; default 'A'
  start: number;         // 1-based DMX start address
}

export interface RawConfig {
  ip: string;
  name?: string;         // platform display name in Homebridge
  yamlPath?: string;
  profiles?: ProfileSpec[];
  patch?: PatchSpec[];
}

export interface Profile {
  name: string;
  model: ColorModel;
  channels: ChannelDef[];
}

export interface Fixture {
  id: string;
  name: string;
  profile: Profile;
  universe: number;      // 0 (A) or 1 (B)
  startCh: number;       // 1..512
  nChannels: number;     // = channels.length
}

export interface LoadedConfig {
  ip: string;
  name: string;
  fixtures: Fixture[];
}

export const DEFAULT_PLATFORM_NAME = 'Stick-DE3 DMX';

/** Load + validate the platform config. `rawJson` is the Homebridge
 *  `platforms[]` entry; if it specifies `yamlPath`, that YAML file is loaded
 *  and treated as a full override of the JSON.
 *
 *  If `cwd` is passed, relative yamlPath is resolved against it. */
export function loadConfig(rawJson: RawConfig, cwd?: string): LoadedConfig {
  let raw: RawConfig = rawJson;
  if (raw.yamlPath) {
    const p = path.isAbsolute(raw.yamlPath) ? raw.yamlPath
            : path.resolve(cwd ?? process.cwd(), raw.yamlPath);
    const text = fs.readFileSync(p, 'utf8');
    const parsed = yaml.load(text) as RawConfig;
    if (!parsed || typeof parsed !== 'object') {
      throw new Error(`yamlPath ${p}: not an object`);
    }
    // YAML overrides JSON, but inherit ip/name if YAML omits them
    raw = { ...rawJson, ...parsed };
  }

  if (!raw.ip || typeof raw.ip !== 'string') {
    throw new Error('config: required field "ip" missing');
  }

  // Profiles
  const profileSpecs = raw.profiles ?? [];
  const profilesByName = new Map<string, Profile>();
  for (const ps of profileSpecs) {
    if (!ps.name) throw new Error('profile: missing name');
    if (profilesByName.has(ps.name)) {
      throw new Error(`profile: duplicate name "${ps.name}"`);
    }
    if (!Array.isArray(ps.channel_order) || ps.channel_order.length === 0) {
      throw new Error(`profile "${ps.name}": channel_order must be a non-empty array`);
    }
    let model: ColorModel;
    try { model = getColorModel(ps.colormodel); }
    catch (e) { throw new Error(`profile "${ps.name}": ${(e as Error).message}`); }
    let channels: ChannelDef[];
    try { channels = ps.channel_order.map(parseChannelName); }
    catch (e) { throw new Error(`profile "${ps.name}" channel_order: ${(e as Error).message}`); }
    try { model.validate(channels); }
    catch (e) { throw new Error(`profile "${ps.name}": ${(e as Error).message}`); }
    profilesByName.set(ps.name, { name: ps.name, model, channels });
  }

  // Patch
  const patchSpecs = raw.patch ?? [];
  const fixtures: Fixture[] = [];
  const seenIds = new Set<string>();
  // 2 universes × 512 channels, tracking which fixture (if any) owns each slot
  const occupancy: Map<number, Map<number, string>> = new Map([[0, new Map()], [1, new Map()]]);

  for (const ps of patchSpecs) {
    if (!ps.id) throw new Error('patch: missing id');
    if (seenIds.has(ps.id)) {
      throw new Error(`patch: duplicate id "${ps.id}"`);
    }
    seenIds.add(ps.id);
    const profile = profilesByName.get(ps.type);
    if (!profile) {
      throw new Error(`patch "${ps.id}": unknown profile "${ps.type}"`);
    }
    const universeChar = (ps.universe ?? 'A').toUpperCase();
    if (universeChar !== 'A' && universeChar !== 'B') {
      throw new Error(`patch "${ps.id}": universe must be 'A' or 'B', got "${ps.universe}"`);
    }
    const universe = universeChar === 'A' ? 0 : 1;
    const nch = profile.channels.length;
    const start = Number(ps.start);
    if (!Number.isInteger(start) || start < 1 || start + nch - 1 > 512) {
      throw new Error(
        `patch "${ps.id}": start ${ps.start} + ${nch} channels does not fit in 1..512`,
      );
    }
    const slots = occupancy.get(universe)!;
    for (let i = 0; i < nch; i++) {
      const slot = start + i;
      const owner = slots.get(slot);
      if (owner) {
        throw new Error(
          `patch "${ps.id}": DMX slot ${slot}@${universeChar} overlaps with "${owner}"`,
        );
      }
      slots.set(slot, ps.id);
    }
    fixtures.push({
      id: ps.id,
      name: ps.name || ps.id,
      profile,
      universe,
      startCh: start,
      nChannels: nch,
    });
  }

  return {
    ip: raw.ip,
    name: raw.name ?? DEFAULT_PLATFORM_NAME,
    fixtures,
  };
}
