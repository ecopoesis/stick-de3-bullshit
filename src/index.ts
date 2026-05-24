// Homebridge plugin entry point.

import type { API } from 'homebridge';
import { PLATFORM_NAME } from './settings.js';
import { StickDe3Platform } from './platform.js';

export default (api: API): void => {
  api.registerPlatform(PLATFORM_NAME, StickDe3Platform);
};
