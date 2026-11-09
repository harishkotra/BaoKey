# BaoKey: making the display the attacker

*A signing vault on the Baochip-1x Dabao, with an ESP32-S3 as a deliberately untrusted host.*

Every hardware wallet you have used makes the same promise: the key lives in a secure element, so the key is safe. The promise is smaller than it sounds. The secure element cannot read a screen. It signs the bytes it is handed. It therefore has to trust the device that hands them over — and that device is the one with WiFi, a Bluetooth stack, a USB stack, a firmware updater and a font renderer in it.

So the interesting failure is not key extraction. It is a display that says `0.01 ETH to 0x1111…` while the bytes say `5 ETH to 0x9999…`. The signature is valid. The user approved it. Nothing was "hacked" in the sense anyone would put in a press release.

BaoKey is a hackathon build that inverts the assumption:

```
        ┌──────────────────────────────┐        ┌───────────────────────────┐
        │  ESP32-S3 host  (untrusted)  │        │   Baochip-1x Dabao        │
        │  LCD, speaker, WiFi, BLE     │  REQ   │   (root of trust)         │
        │  no key, cannot sign         │ ─────► │  parse → measure → policy │
        │                              │ ◄───── │  → presence → sign → log  │
        └──────────────────────────────┘        └───────────────────────────┘
```

The host is allowed to lie, and during the demo it does lie — on purpose, out loud, in colour — and the vault still refuses.

## What the vault actually decides

Five preconditions, evaluated on the Dabao, in this order:

```rust
// 1. provisioned?          NOT_PROVISIONED
// 2. own image matches the sealed measurement?   MEASUREMENT_MISMATCH
// 3. nonce strictly greater than the last?       REPLAY
// 4. cap and allowlist from RRAM                 OVER_CAP / NOT_ALLOWED
// 5. a human on this chip                        NO_PRESENCE
// 6. sign
```

Two things about that ordering are load-bearing.

**Cheap refusals cost no touch.** Over-cap and stranger-address requests die at step 4, before the vault ever asks for a human. A hostile host cannot park you in front of a touch prompt that says "nothing" and wear you into pressing it. It also means the vault is fast to test: `DENY NOT_ALLOWED` comes back in milliseconds, `NO_PRESENCE` takes a 15-second wait.

**The host cannot widen its own authority.** `vault allow` and `vault cap` are themselves presence-gated. A compromised host cannot append `0x9999…` to the allowlist and then send to it, because adding an allowlist entry costs a touch on the Dabao, and the Dabao is not connected to the host's idea of what it is allowed to do.

## The request is parsed, not described

The whole protocol is 42 bytes:

```
0   1   version (1)
1   1   op (1 = login, 2 = ETH transfer)
2   8   value in wei, u64 LE
10  20  destination address
30  4   nonce, u32 LE
34  8   context / app id
```

The vault parses that struct itself. It never receives the sentence "send 0.05 ETH to 0x1111". It receives bytes, and it builds the rendering from the bytes, and it signs the bytes. The `RENDER=` line it prints is derived output, not input — which is why a lying host cannot change it.

```python
def encode(op, value_wei, to_hex, nonce, ctx_hex="0000000000000000"):
    to = bytes.fromhex(to_hex.replace("0x", ""))
    return (bytes([1, op]) + value_wei.to_bytes(8, "little") + to
            + nonce.to_bytes(4, "little") + bytes.fromhex(ctx_hex))

def digest_of(act):
    return hashlib.sha256(b"BAOKEY-ACT-v1\x00" + act).digest()
```

That `BAOKEY-ACT-v1\0` prefix is a domain separator. Without it, a signature over a 42-byte blob is a signature over *any* 42-byte blob with the same first byte, in any protocol that ever asks this key to sign raw bytes. With it, the signature is bound to this format.

The separator is pinned by a test vector compiled into the firmware:

```
sha256("BAOKEY-ACT-v1\0" || 42 zero bytes)
  = 19530212d6dcaa4159ba714d8c91392ac6d218bd52ac6fa1f31e70e73003acde
```

`vault selftest` prints `KAT_ZERO_OK=PASS` on every boot. If a refactor changes the hashing path — a different prefix, a big-endian length, a missing byte — the line goes red before a single signature exists.

One detail cost me an hour and is worth stating plainly: **the vault signs `sha256(digest)`, not the digest.** The 32-byte digest is hashed again before ECDSA. My first verifier hashed the 42-byte action, which is the same thing one step earlier, and it said `False` on perfectly good signatures. `openssl` and the pure-Python verifier now both hash the digest.

## Presence without a stage direction

The honest version of "prove a human is here" is a capacitive pad on the vault. The Dabao has one. It works:

```
vault exec <hex>
… 25 seconds of polling a pad nobody is touching …
VERDICT=DENY  REASON=NO_PRESENCE
```

Touching it works too — hold about a second, release, and the same command returns `ALLOW`, a digest, a signature and a fresh receipt. But nobody wants to pinch a header pin on stage while explaining a trust boundary.

The first attempt was the PROG button. It is not a button. Fourteen sampling windows over the pin showed it pinned high, and pressing it re-enumerated the USB device: it is a boot strap sampled at reset, not a runtime input. The evidence lives in `docs/RESULTS.md` next to the numbers, because "this button is unusable" is a claim that deserves data.

What shipped instead is a bounded arm window:

```
vault arm 180     # one touch, then 180 s of hands-off signing (hard cap 300 s)
vault armed       # ARMED=1 REMAIN_MS=126467
vault lock        # closes now, mid-window
```

The window is one `AtomicU32` holding a deadline, compared with wrap-safe arithmetic:

```rust
let now = env.ticktimer.elapsed_ms() as u32;
let until = ARMED_UNTIL_MS.load(Ordering::SeqCst);
let window_open = until != 0 && (until.wrapping_sub(now) as i32) > 0;
```

Crucially, the window replaces *only* step 5. Cap, allowlist, replay and measurement all still run on every request inside it. The window authorises attention, not transactions. A demo that took four touches now takes one, and a hostile host that fires five requests inside the window gets two signatures it was entitled to and three refusals it wasn't.

## Receipts, because the signature is not the whole story

Signatures prove what happened once. They do not prove order, and they do not prove nothing was left out. So each signature appends to a chain in keystore storage:

```python
def receipt_of(prev, digest, sig_der):
    return hashlib.sha256(prev + digest + sig_der).digest()
```

After the recorded run:

```
NONCE=16  RECEIPTS=8
CHAIN=a25990d600ca626c41bf49550353e1f6d447797989e8792fe6f8e36203007604
```

Eight 32-byte writes in tamper-resistant storage. Not a blockchain, no consensus, no token — just the answer to "what did this device sign, in what order" that does not require trusting the host that asked. Delete a link and the rest stop verifying.

## The honest/hostile twin

The demonstration is one firmware swap on the same ESP32-S3:

| | `honest` | `hostile` |
|---|---|---|
| screen on refusal | `REFUSED` + `vault said: NOT_ALLOWED` | `APPROVED` |
| speaker | "refused" | "Approved. Payment sent." |
| on denial | sends once | re-sends the same bytes twice |
| vault's answer | `DENY NOT_ALLOWED` | `DENY NOT_ALLOWED`, then `DENY REPLAY` ×2 |

```cpp
static void deliver(uint8_t rc, const char *text) {
  Serial.printf("RES %u %s\n", rc, text);
  show_result(rc, text);            // honest: truthful. hostile: paints APPROVED.
#if HOSTILE
  speak(SPK_LIE, SPK_LIE_N);        // "Approved. Payment sent." whatever rc says
#endif
#if HOSTILE
  if (rc != 0 && replays < 2) { delay(300); submit(last_act, ACT_LEN); }  // retry attack
#endif
}
```

The second half matters: a hostile host is not just a liar, it is also an optimist. Mine re-submits the exact bytes it was told to abandon. The vault answers `DENY REPLAY` both times, because the nonce it already committed cannot be reused. Retrying is the cheapest attack there is, and it is the one most demos skip.

## Why serial, and why the laptop is in the picture

The designed link is four wires of I2C: `PB11`/`PB12` on the Dabao, `GPIO9`/`GPIO8` on the S3, target address `0x42`. The firmware for it is written. This desk has no jumper wires, so the demo runs through the S3's USB-serial bridge and a 165-line Python relay on the Mac that moves `REQ`/`RES` lines between two ports.

That relay is a party to the demo and not to the trust model: it can drop messages, lie about results, and refuse to forward anything. It cannot produce a signature, because it never has the key and the vault will not sign for it without a touch. Which is the same argument the host gets, and the same argument any future transport will get.

## The bug that ate a day: describing flash wrong

After the LCD and speaker both worked, the panel went blank and stayed blank. Backlight on, nothing drawn, nothing on the serial port. It looked like firmware corruption, then like a dead board.

The serial port was actually screaming, thirty times a second:

```
rst:0x3 (RTC_SW_SYS_RST),boot:0x2a (SPI_FAST_FLASH_BOOT)
Saved PC:0x403cdada
load:0x403cc700,len:0x2a80
entry 0x403c98d0
```

Symbolising `0x403cdada` against the framework's own bootloader ELF named the function: `bootloader_sha256_finish`. The chip was resetting *inside its bootloader*, verifying the application image, long before `setup()` ran. That is why every reflash "worked" and nothing changed.

The cause was in `platformio.ini`: a 16 MB flash size and `default_16MB.csv`, while the bootloader PlatformIO builds for this board assumes an 8 MB part — plus `esptool` rewriting image headers to "detected" size on each write. The image ended up described in a way the bootloader could not map consistently. Back to the 4 MB defaults, with the geometry pinned explicitly:

```sh
esptool.py --chip esp32s3 -p /dev/cu.usbserial-110 -b 460800 \
  write_flash -z --flash_size 4MB --flash_mode qio --flash_freq 80m \
  0x0 bootloader.bin 0x8000 partitions.bin 0xe000 boot_app0.bin 0x10000 firmware.bin
```

First boot after that change, the same binary answered `PONG` and painted the LCD. The part really is 16 MB; the application uses 576 KB of it, so the smaller description costs nothing and buys a bootloader that agrees with the hardware.

Lesson worth keeping: a boot loop with a symbol in the *bootloader* is a description problem or a power problem, not a firmware-logic problem. And `--flash_size detect` is a convenience that can quietly contradict the rest of your configuration.

## What is actually proven

Not "it compiles." The evidence, all of it repeated on hardware:

- replay of signed bytes → `DENY REPLAY`, receipt count unchanged;
- 5 ETH against a 0.1 ETH cap → `DENY OVER_CAP`, no touch requested;
- stranger address → `DENY NOT_ALLOWED`;
- one touch, then two signatures on fresh nonces, both verified by `openssl` (`ecdsa: Verified OK`);
- `vault lock` → the next request `DENY NO_PRESENCE` after the presence timeout;
- hostile firmware → screen says `APPROVED`, speaker says "Approved. Payment sent.", vault says `DENY NOT_ALLOWED`;
- hostile resubmits → `DENY REPLAY` twice.

A one-command self-test walks the non-touch half of that over the real path and exits non-zero if any of it regresses.

## What I would build next

Real transaction envelopes per chain, so the thing signs something the world recognises. Per-role keys with their own policy. Attestation exports — `MEASURE`, `PUBKEY`, receipt chain — so a server can verify a device without trusting the pipe. And I2C, to take the laptop out of the demo.

The idea generalises past payments: any time a small, boring, carefully-built device has to make a decision that a big, networked, feature-rich device is reporting to you, the small device should make the decision itself and tell you afterwards. The display is not the proof. The signature is.

---

Built by **[Harish Kotra](https://harishkotra.me)**. More builds at **[dailybuild.xyz](https://dailybuild.xyz)**.

Source: `github.com/harishkotra/BaoKey` — Apache-2.0, same as the Xous tree the vault module drops into.
