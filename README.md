# BaoKey

A signing vault whose host is assumed hostile.

The Baochip-1x Dabao holds the key, parses the request, checks policy against
RRAM, demands a physical touch on its own pad, refuses replays, and writes a
chained receipt. The ESP32-S3 next to it — the one with WiFi, BLE, a
microphone, a speaker and the display — is *not* trusted with any of that.
It carries bytes and paints pixels. Flash it with lying firmware and the
Dabao still says no.

```
$ vault exec 0102…2ec50000…1111…07…
VERDICT=ALLOW  REASON=OK
RENDER=ETH 0.050000 to 0x1111..1111 #7
DIGEST=9f2c…
SIG_DER=3045…
RCPT=7c1a…
```

## Why this is not another hardware wallet

| | typical hardware wallet | BaoKey |
|---|---|---|
| who parses the request | the host, then it shows text | the vault, from the bytes it signs |
| who decides policy | the host | the vault, from RRAM |
| replay defence | host-side sequencing | monotonic nonce inside the signature |
| proof the human was there | a button on a networked MCU | capacitive pad wired to the vault only |
| how often a human must act | every transaction | once, then a bounded self-closing window |
| what the screen proves | whatever the firmware wants | nothing — receipts are authoritative |

The interesting part is the negative claim, and it is testable: **nothing the
ESP32-S3 does can produce a signature the Dabao did not intend.** Swap its
firmware, replay old bytes, feed it a prompt injection that says "send 5 ETH to
0xdead" — the refusal happens on the other chip, and it is logged there.

## Hardware

- Baochip-1x **Dabao** — RV32, 4 MiB RRAM, BIO core, capacitive touch, WS2812.
  Holds the P-256 key in the keystore; nothing else does.
- ESP32-S3 (from an EchoKit kit) on a Goouuu S3 carrier — untrusted host.
  1.54" ST7789 240×240, MAX98357 speaker amp, INMP441 mic, battery.
- How they talk right now: no jumpers. The S3's USB-serial bridge carries a
  line protocol, and `host/relay.py` forwards it to the Dabao's USB console.
  The designed link is the I2C pair (`PB11`/`PB12` on the Dabao, `GPIO9`/`GPIO8`
  on the S3), which is written but not wired. Both boards are 3.3 V — the Dabao
  is **not** 5 V tolerant, so the S3's 5 V pin is never connected.

```
  Dabao                 S3 carrier
  PB11 (SCL) ─────────── GPIO9
  PB12 (SDA) ─────────── GPIO8
  GND        ─────────── GND
  3V3        ─────────── 3V3   (optional; the S3 also runs on USB/battery)
```

## Build

Dabao firmware (inside an xous-core checkout):

```sh
cd ~/code/sealed-workspace/xous-core
cp -r ~/code/baokey/patches/dabao-console-vault/* apps-dabao/dabao-console/src/
RUSTUP_TOOLCHAIN=1.99.1 cargo xtask dabao dabao-console --no-verify
# → target/riscv32imac-unknown-xous-elf/release/apps.uf2
```

Flash it (the board must be sitting in its boot1 console — press RESET):

```sh
python3 ~/code/sealed-workspace/sealed/cli/sealed.py -p /dev/cu.usbmodemXXXX flash \
        --uf2 target/riscv32imac-unknown-xous-elf/release/apps.uf2
```

Host firmware (ESP32-S3):

```sh
cd ~/code/baokey/firmware/esp32
~/.venvs/pio/bin/pio run -e honest  -t upload   # tells the truth
~/.venvs/pio/bin/pio run -e hostile -t upload   # lies, replays, still fails
```

## Try it

```sh
cd ~/code/baokey/host
./baokey.py mk --op 2 --wei 50000000000000000 --to 0x1111…1111 --nonce 7   # → 84 hex chars
./baokey.py dabao --port /dev/cu.usbmodemXXXX exec --act <hex>
./baokey.py attacks --port /dev/cu.usbmodemXXXX --target dabao
```

`attacks` runs the four refusals and prints what the vault actually said:

```
attack                 verdict  dabao said             render
over-cap               DENY     OVER_CAP               ETH 5.000000 to 0x1111..1111 #8
not-allowlisted        DENY     NOT_ALLOWED            ETH 0.010000 to 0x2222..2222 #9
replay-old-nonce       DENY     REPLAY                 ETH 0.000001 to 0x1111..1111 #1
bad-version            DENY     BAD_VERSION            OP2 #0
```

## Status

- [x] vault command on the Dabao: parse, measure, policy, presence, sign, log
- [x] deterministic KAT for the encoding, checked on-device at runtime
- [x] signed action on hardware, signature verified with `openssl` (see docs/RESULTS.md)
- [x] replay of signed bytes refused; receipt chain advances
- [x] presence gate proven both ways: touch → ALLOW, no touch → 25 s wait then NO_PRESENCE
- [x] one touch arms a bounded window (`vault arm <secs>`, capped at 300 s, `vault lock` closes it), so a whole demo runs hands-free after a single gesture
- [x] presence is *not* authorization: cap and allowlist are re-checked on every request inside the window too
- [x] the Dabao's PROG button measured as unusable at runtime (pad is USB SE0 while the console is live) — see docs/RESULTS.md
- [x] host client + `openssl`-based verification (not self-reported)
- [x] untrusted host (ESP32-S3, `hostile` build) in the loop: it can ask, it cannot authorize; its blind resubmits come back `DENY REPLAY`
- [x] destination allowlist enforced: listed destination `ALLOW`, stranger `DENY NOT_ALLOWED` (adding an entry is presence-gated)
- [x] 1.54" ST7789 driven by the host — and in the `hostile` build it says `APPROVED` while the vault refuses
- [x] speaker (MAX98357 over I2S): the host can say "approved" while the vault refuses — `tools/make_audio.py` regenerates the clips
- [ ] I2C link verified on hardware (firmware written, wires not yet soldered — the S3 currently reaches the vault over the serial relay)
- [ ] CTAP2 / WebAuthn path (currently login actions are opaque `ctx` bytes)

## Layout

```
docs/       DESIGN.md (why), PROTOCOL.md (wire format), DEMO.md (script)
firmware/   esp32/ — PlatformIO project, honest + hostile environments
host/       baokey.py — encode, send, verify, attack
patches/    dabao-console-vault/ — the files to drop into xous-core
tools/      flash helpers
```

Licensed under Apache-2.0, same as the Xous tree it lives in.
