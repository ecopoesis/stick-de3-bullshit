// Config loader + validator.
//
// Inputs:
//   - Homebridge config: `platforms[].DMX` block from Homebridge's
//     config.json. Optional `yamlPath` points to an external YAML file
//     whose contents take precedence over the JSON.
//   - YAML override: same shape as the JSON block.
//
// Shape:
//   {
//     "platform": "DMX",
//     "name": "DMX",
//     "yamlPath": "/optional/path/to/dmx.yaml",
//     "controllers": [
//       { "id": "main", "type": "StickDE3", "ip": "192.168.96.2" }
//     ],
//     "profiles": [
//       { "name": "WAC", "colormodel": "hsvcct",
//         "channel_order": ["Intensity", "Intensity (Fine)",
//                           "ColorTemp 1650-8000", "Saturation", "Hue"] }
//     ],
//     "patch": [
//       { "id": "a_down", "name": "A Down", "type": "WAC",
//         "controller": "main", "universe": "A", "start": 6 }
//     ]
//   }
//
// Output: a normalized `LoadedConfig` the platform consumes. Validates:
//   - controllers: unique ids, supported type, ip present
//   - profiles: colormodel recognised, channel_order parses cleanly, model
//     requirements satisfied
//   - patch: unique ids, references a known profile + controller, valid
//     universe ∈ {A,B}, start in [1, 512-nch+1], no slot overlap within a
//     single (controller, universe).

import fs from 'node:fs';
import path from 'node:path';
import yaml from 'js-yaml';

import { ChannelDef, ColorModel, HKCharacteristic } from './color/types.js';
import { getColorModel } from './color/index.js';
import { parseChannelName } from './color/parsers.js';

export interface ControllerSpec {
  id: string;            // unique handle, referenced from patch entries
  type: string;          // 'StickDE3' (only one supported today)
  ip: string;            // controller's static IP
}

export interface ProfileSpec {
  name: string;
  colormodel: string;
  channel_order: string[];
}

export interface PatchSpec {
  id: string;            // unique handle (kebab-case)
  name: string;          // human-friendly HomeKit name
  type: string;          // profile name (refers to a ProfileSpec.name)
  controller?: string;   // controller id; required if >1 controller configured
  universe?: string;     // 'A' or 'B'; default 'A'
  start: number;         // 1-based DMX start address
}

export interface ZoneSpec {
  id: string;            // unique handle (kebab-case)
  name: string;          // human-friendly HomeKit name
  members: string[];     // fixture ids included in this zone
}

export interface RawConfig {
  name?: string;
  yamlPath?: string;
  controllers?: ControllerSpec[];
  profiles?: ProfileSpec[];
  patch?: PatchSpec[];
  zones?: ZoneSpec[];
}

export interface Profile {
  name: string;
  model: ColorModel;
  channels: ChannelDef[];
}

export const CONTROLLER_TYPES = ['StickDE3'] as const;
export type ControllerType = typeof CONTROLLER_TYPES[number];

export interface Controller {
  id: string;
  type: ControllerType;
  ip: string;
}

export interface Fixture {
  id: string;
  name: string;
  profile: Profile;
  controller: Controller;
  universe: number;      // 0 (A) or 1 (B)
  startCh: number;       // 1..512
  nChannels: number;     // = channels.length
}

/** A virtual "zone" Lightbulb: appears as a single accessory in HomeKit;
 *  setting its state dispatches to every member fixture. The intersection
 *  of the members' color-model characteristics is what HomeKit sees. */
export interface Zone {
  id: string;
  name: string;
  members: Fixture[];
  characteristics: HKCharacteristic[];   // intersection of member characteristics
}

export interface LoadedConfig {
  name: string;
  controllers: Controller[];
  fixtures: Fixture[];
  zones: Zone[];
}

export const DEFAULT_PLATFORM_NAME = 'DMX';

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
    raw = { ...rawJson, ...parsed };
  }

  // Controllers
  const controllerSpecs = raw.controllers ?? [];
  if (controllerSpecs.length === 0) {
    throw new Error('config: at least one controller required under "controllers"');
  }
  const controllersById = new Map<string, Controller>();
  for (const cs of controllerSpecs) {
    if (!cs.id) throw new Error('controller: missing id');
    if (controllersById.has(cs.id)) {
      throw new Error(`controller: duplicate id "${cs.id}"`);
    }
    if (!CONTROLLER_TYPES.includes(cs.type as ControllerType)) {
      throw new Error(
        `controller "${cs.id}": unknown type "${cs.type}". ` +
        `Supported: ${CONTROLLER_TYPES.join(', ')}`,
      );
    }
    if (!cs.ip || typeof cs.ip !== 'string') {
      throw new Error(`controller "${cs.id}": required field "ip" missing`);
    }
    controllersById.set(cs.id, { id: cs.id, type: cs.type as ControllerType, ip: cs.ip });
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
  // Per controller + per universe: 512 channels, tracking which fixture
  // owns each slot. Key is `${controllerId}:${universe}`.
  const occupancy: Map<string, Map<number, string>> = new Map();
  const slots = (cid: string, u: number): Map<number, string> => {
    const key = `${cid}:${u}`;
    let m = occupancy.get(key);
    if (!m) { m = new Map(); occupancy.set(key, m); }
    return m;
  };

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
    // controller reference. If only one controller is configured, default to it.
    let controllerId = ps.controller;
    if (!controllerId) {
      if (controllersById.size === 1) {
        controllerId = controllersById.keys().next().value as string;
      } else {
        throw new Error(
          `patch "${ps.id}": "controller" required when more than one controller is configured`,
        );
      }
    }
    const controller = controllersById.get(controllerId);
    if (!controller) {
      throw new Error(`patch "${ps.id}": unknown controller "${controllerId}"`);
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
    const slotMap = slots(controllerId, universe);
    for (let i = 0; i < nch; i++) {
      const slot = start + i;
      const owner = slotMap.get(slot);
      if (owner) {
        throw new Error(
          `patch "${ps.id}": DMX slot ${slot}@${universeChar} ` +
          `(controller "${controllerId}") overlaps with "${owner}"`,
        );
      }
      slotMap.set(slot, ps.id);
    }
    fixtures.push({
      id: ps.id,
      name: ps.name || ps.id,
      profile,
      controller,
      universe,
      startCh: start,
      nChannels: nch,
    });
  }

  // Zones — virtual Lightbulb accessories. Each zone's members must be
  // existing fixture ids. Zones never reference other zones (no recursion).
  const fixturesById = new Map(fixtures.map((f) => [f.id, f]));
  const zoneSpecs = raw.zones ?? [];
  const zones: Zone[] = [];
  const seenZoneIds = new Set<string>();
  for (const zs of zoneSpecs) {
    if (!zs.id) throw new Error('zone: missing id');
    if (seenZoneIds.has(zs.id)) {
      throw new Error(`zone: duplicate id "${zs.id}"`);
    }
    if (fixturesById.has(zs.id)) {
      throw new Error(`zone id "${zs.id}" collides with fixture id`);
    }
    seenZoneIds.add(zs.id);
    if (!Array.isArray(zs.members) || zs.members.length === 0) {
      throw new Error(`zone "${zs.id}": members must be a non-empty array of fixture ids`);
    }
    const members: Fixture[] = [];
    for (const m of zs.members) {
      const fx = fixturesById.get(m);
      if (!fx) {
        throw new Error(`zone "${zs.id}": unknown fixture "${m}"`);
      }
      members.push(fx);
    }
    // Intersection of member characteristics — HomeKit only exposes what
    // ALL members can do.
    let chars = new Set<HKCharacteristic>(members[0].profile.model.characteristics);
    for (let i = 1; i < members.length; i++) {
      const mc = new Set<HKCharacteristic>(members[i].profile.model.characteristics);
      chars = new Set([...chars].filter((c) => mc.has(c)));
    }
    zones.push({
      id: zs.id,
      name: zs.name || zs.id,
      members,
      characteristics: [...chars],
    });
  }

  return {
    name: raw.name ?? DEFAULT_PLATFORM_NAME,
    controllers: [...controllersById.values()],
    fixtures,
    zones,
  };
}
