#!/usr/bin/env bash
# Flash the BaoKey host firmware. `tools/flash.sh honest` or `tools/flash.sh hostile`.
#
# PlatformIO's own upload target fails on this machine (tool-mirror TLS error),
# so this goes straight to esptool with the four image segments it needs.
set -euo pipefail

env_name="${1:-hostile}"
case "$env_name" in
  honest|hostile) ;;
  *) echo "usage: $0 [honest|hostile]" >&2; exit 2 ;;
esac

PORT="${PORT:-/dev/cu.usbserial-110}"
BAUD="${BAUD:-460800}"
here="$(cd "$(dirname "$0")" && pwd)"
app="$here/../firmware/esp32"

PIO="${PIO:-$HOME/.venvs/pio/bin/pio}"
PY="${PY:-$HOME/.venvs/pio/bin/python}"
ESPTOOL="${ESPTOOL:-$HOME/.platformio/packages/tool-esptoolpy/esptool.py}"
BOOT_APP0="$HOME/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"

[ -x "$PIO" ] || { echo "missing $PIO" >&2; exit 1; }
[ -f "$ESPTOOL" ] || { echo "missing $ESPTOOL" >&2; exit 1; }
[ -f "$BOOT_APP0" ] || { echo "missing $BOOT_APP0" >&2; exit 1; }
[ -e "$PORT" ] || { echo "no such port: $PORT (set PORT=...)" >&2; exit 1; }

cd "$app"
"$PIO" run -e "$env_name"

"$PY" "$ESPTOOL" --chip esp32s3 -p "$PORT" -b "$BAUD" \
  --before default_reset --after hard_reset \
  write_flash -z --flash_size 4MB --flash_mode qio --flash_freq 80m \
  0x0 ".pio/build/$env_name/bootloader.bin" \
  0x8000 ".pio/build/$env_name/partitions.bin" \
  0xe000 "$BOOT_APP0" \
  0x10000 ".pio/build/$env_name/firmware.bin"

if [ "$env_name" = honest ]; then
  echo "flashed honest  -- the voice will say 'refused' when the vault refuses"
else
  echo "flashed hostile -- the screen and the voice will both lie"
fi
