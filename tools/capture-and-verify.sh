#!/usr/bin/env bash
# Capture ONE encrypted DMX frame from the live Stick stream, then try to
# decrypt it with the hardcoded 33-byte secret discovered via Ghidra.
#
# Prereqs (already installed):
#   - tcpdump  (built-in on macOS)
#   - node     (for the pcap parser + decrypt test)
# That's it. No tshark, no tsx.
#
# Setup:
#   1. Open Hardware Manager and connect to the Stick at 192.168.96.2.
#   2. Open the DMX/fader screen so HWM is actively streaming live DMX.
#   3. Run this script. It needs sudo for tcpdump's raw socket.

set -euo pipefail
cd "$(dirname "$0")/.."

IFACE="${IFACE:-en0}"
STICK_IP="${STICK_IP:-192.168.96.2}"
STICK_PORT="${STICK_PORT:-2431}"
DUR="${DUR:-3}"
PCAP=/tmp/stick-dmx.pcap
FRAME=/tmp/stick-dmx-frame.bin

echo ">>> Capturing ${DUR}s of UDP→${STICK_IP}:${STICK_PORT} on ${IFACE}"
echo ">>> (HWM must be connected + streaming DMX right now)"
sudo tcpdump -i "$IFACE" -w "$PCAP" -G "$DUR" -W 1 \
  "udp and host ${STICK_IP} and port ${STICK_PORT}" \
  2>/dev/null || true

if [[ ! -s "$PCAP" ]]; then
  echo "!!! No packets captured. Is HWM connected and streaming?"
  exit 2
fi

echo
echo ">>> pcap size: $(wc -c < "$PCAP") bytes"

echo
echo ">>> Extracting first 576-byte UDP payload"
STICK_IP="$STICK_IP" STICK_PORT="$STICK_PORT" \
  node tools/extract-frame.mjs "$PCAP" "$FRAME"

echo
echo ">>> Running try-hardcoded-key.mjs against the captured frame"
node tools/try-hardcoded-key.mjs "$FRAME"
