# homebridge-dmx

Homebridge platform plugin that exposes DMX fixtures as HomeKit Lightbulb
accessories. The DMX controller is abstracted so additional controllers can be
plugged in without rewriting your patch; the supported controller today is the
**Nicolaudie Stick-DE3** (TCP/2431 + AES-256-CBC-encrypted 576-byte UDP DMX
stream, reverse-engineered from the ESA2 Hardware Manager).

[![npm](https://img.shields.io/npm/v/@ecopoesis/homebridge-dmx.svg)](https://www.npmjs.com/package/@ecopoesis/homebridge-dmx)

## Status

| Piece | State |
| --- | --- |
| Stick-DE3 control (auth, ECDH, encrypted DMX stream) | ✅ working |
| Color models: dimmer, cct, rgb, rgbw, rgbww, rgbaw, hsvcct | ✅ |
| YAML and Homebridge-UI config | ✅ |
| Multiple controllers in one patch | ✅ (only `StickDE3` type supported today) |
| Universe B on the Stick | 🚧 plumbed but the wire encoding is unknown |
| Stick-DE3 password / "Cloud Access" auth | 🚧 not implemented |
| State read-back | 🚧 Homebridge holds the canonical state; local drift accepted |

## How it works

Each HomeKit change is rendered into DMX bytes by the fixture's color model
(HSV → channel values for the appropriate model), written into a per-universe
buffer, and dispatched via a debounced controller. After 750 ms of quiet (or
during a slider drag, continuously), the controller spawns
**`tools/send_dmx.mjs`** as a child process which runs the full Stick-DE3
handshake + 750 ms of 25 Hz encrypted UDP frames + a dirty close (RST → Stick
latches the last values).

The subprocess-per-transaction architecture is an empirical workaround:
running the same protocol in-process in a long-lived plugin only worked for
the first transaction; sessions 2+ silently failed to drive output. Running
each transaction in a fresh node process bypasses whatever in-process state
poisons subsequent sessions. Each transaction costs ~1.5–2 s total.

## Install

```bash
npm install -g @ecopoesis/homebridge-dmx
```

Or, in the Homebridge UI: **Plugins** → search for "DMX" → install.

## Config

Two flavours: inline JSON via the Homebridge UI, or external YAML pointed to by
`yamlPath`. YAML is recommended for anything beyond a couple of fixtures.

Minimal inline config:

```json
"platforms": [
  {
    "platform": "DMX",
    "name": "DMX",
    "controllers": [
      { "id": "main", "type": "StickDE3", "ip": "192.168.96.2" }
    ],
    "profiles": [
      {
        "name": "WAC",
        "colormodel": "hsvcct",
        "channel_order": [
          "Intensity", "Intensity (Fine)",
          "ColorTemp 1650-8000",
          "Saturation", "Hue"
        ]
      }
    ],
    "patch": [
      { "id": "a_down", "name": "A Down", "type": "WAC", "controller": "main", "start": 6 }
    ]
  }
]
```

External YAML form (recommended):

```json
"platforms": [
  { "platform": "DMX", "yamlPath": "/homebridge/dmx.yaml" }
]
```

See [`examples/dmx.yaml`](examples/dmx.yaml) for a starting point.

## Color models

| Model | Channels | HomeKit characteristics |
| --- | --- | --- |
| `dimmer` | 1 (Intensity, +optional Fine) | On, Brightness |
| `cct` | 2 (Intensity, ColorTemp `KMin-KMax`) | On, Brightness, ColorTemperature |
| `rgb` | 3 (Red, Green, Blue — any order) | On, Brightness, Hue, Saturation |
| `rgbw` | 4 (+ White; W = min(R,G,B)) | On, Brightness, Hue, Saturation |
| `rgbww` | 5 (+ WarmWhite, CoolWhite — split by CCT) | On, Brightness, Hue, Saturation, ColorTemperature |
| `rgbaw` | 5 (+ Amber, White) | On, Brightness, Hue, Saturation |
| `hsvcct` | 5 (Intensity, Intensity (Fine), ColorTemp, Saturation, Hue) | All five characteristics; HomeKit-native (the WAC DC-WD05 layout) |

Channel-name syntax:

- `(Fine)` appended → 16-bit companion to the preceding channel
  (e.g. `Intensity (Fine)` is the low byte of a 16-bit intensity).
- CCT channels carry a Kelvin range: `ColorTemp 1650-8000`,
  `WarmWhite 2700`, `CoolWhite 6500`.
- Names are case-insensitive and recognise common aliases (`R`/`Red`,
  `WW`/`Warm White`/`WarmWhite`, etc.).

## CLI

A `stick` CLI is included for hand-testing without Homebridge:

```bash
# Set channel 6 of universe A to 255 on a Stick at 192.168.96.2
npx -p @ecopoesis/homebridge-dmx stick 192.168.96.2 uA,6=255

# Named fixture from your YAML
stick --config ~/.config/dmx.yaml 192.168.96.2 a_down=#ff8800
```

Value forms: `#rrggbb`, `#rgb`, `hsl(120, 100%, 50%)`, `hwb(180 10% 20%)`,
`rgb(255,128,0)`, `kelvin(2700)`, `0..255` (dimmer profiles), `on`, `off`,
`50%`.

## Required Stick-DE3 device setup

Brand-new (or factory-reset) Stick-DE3 devices ship with pathological DMX
output timing. Symptom: every DMX change applies ~2–3 minutes late then snaps.
Fix via **USB-connected Hardware Manager** → DMX/fader screen → set
**Standard/Recommended** (MBB 100 / Break 180 / MAB 20 / MBS 4). This screen
is USB-only; a factory Reset does NOT fix it. See `CLAUDE.md` →
"Required device setup" for the full landmine.

## Single-session lock

While the plugin is mid-transaction (~1.5 s per change), the Stick is unusable
from Hardware Manager (single TCP/2431 session, mutually exclusive). For an
idle Homebridge the Stick is free for HWM commissioning at all other times.
The latch model (clean disconnect leaves the last value lit) is what lets us
be polite about this.

## License

Apache-2.0
