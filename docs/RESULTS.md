# Hardware results

Every line below is copied from a serial capture of the Dabao (serial `V6VJDB`,
boot1 `v0.10.0-61-g5397e1b48`, stepping A0), 2026-11-09. Nothing here is a
projection.

## Provision

```
vault init
PROVISIONED=1
CAP_WEI=100000000000000000
```

```
vault status
BAOKEY v1
PROVISIONED=1
CAP_WEI=100000000000000000
ALLOW_N=0
NONCE=0
RECEIPTS=0
MEASURE=3eecd519bfeb9e39da607e8aaf7f795c15f6013ef0c200edb5f3941488bbdd8e
PUBKEY=041277c6c58f2386c299c843d55e6ee5ec0389b3d329e997383ca2acb8ace759bdc6f5c7584f115cdf6de78350310facf3bc5ba472867f396fc7fa7c6738aea453
```

## Known-answer test on device

`KAT_ZERO` was computed in Python *before* the Rust existed, from the spec
`sha256("BAOKEY-ACT-v1\x00" || 42 zero bytes)`:

```
vault selftest
KAT_ZERO=19530212d6dcaa4159ba714d8c91392ac6d218bd52ac6fa1f31e70e73003acde
KAT_ZERO_OK=PASS
ENC_LEN=42
POLICY_0=PASS
POLICY_1=PASS
POLICY_2=PASS
```

## Two independent implementations agree on the digest

Board, for the 0.05 ETH action: `DIGEST=367c6072ed17c344aec74de89214f56a9bf07b766a0a706c428341d4cfe7c970`
Python, same bytes: `367c6072ed17c344aec74de89214f56a9bf07b766a0a706c428341d4cfe7c970`

## Policy, without signing

```
vault check <0.05 ETH to 0x1111..>  → VERDICT=ALLOW  REASON=ALLOW_DRYRUN
vault check <5 ETH to 0x1111..>     → VERDICT=DENY   REASON=OVER_CAP
vault check <0.01 ETH to 0x2222..>  → VERDICT=ALLOW  REASON=ALLOW_DRYRUN
```

## The signed path (touch on BIO pin 1)

```
vault exec <0.05 ETH to 0x1111.. nonce 7>
VERDICT=ALLOW
REASON=ALLOW
RENDER=ETH 0.050000 to 0x1111..1111 #7
DIGEST=367c6072ed17c344aec74de89214f56a9bf07b766a0a706c428341d4cfe7c970
SIG_DER=304502206d51113262fad06db098fd67e4a7c316c1846a607dde033b6efc8ff424ca597b022100b22f9dce14e4e6d0963057db35385fe86c22b5bc9cdc6f970ec4dee84d3ee978
RCPT=b0a2c5a264a4c29db299e6883c5e2714e15355ca40387efaa59c193664438319
SEQ=1
```

Verified outside the vault, with openssl rather than our own code:

```
# openssl: VERIFIED (Verified OK)
```

## Presence is not a formality

Same action, new nonce, nobody touching the pad:

```
elapsed=25.0s VERDICT=DENY REASON=NO_PRESENCE
```

25 seconds of waiting, then a refusal. Earlier, with a finger on the pad, the
same command returned `ALLOW`. So the gate is doing the work, and the timeout
does not silently pass.

## Replay

```
vault exec <identical bytes as the ALLOW above>
VERDICT=DENY
REASON=REPLAY
```

The refusal did not advance the counter, and the vault remembers where it got to:

```
vault status
PROVISIONED=1
CAP_WEI=100000000000000000
ALLOW_N=0
NONCE=7
RECEIPTS=1
CHAIN=b0a2c5a264a4c29db299e6883c5e2714e15355ca40387efaa59c193664438319
```

## Receipt chain

```
vault rcpt
RECEIPTS=1
CHAIN=b0a2c5a264a4c29db299e6883c5e2714e15355ca40387efaa59c193664438319
LAST=b0a2c5a264a4c29db299e6883c5e2714e15355ca40387efaa59c193664438319
```

## Untrusted host over the serial relay

The ESP32-S3 cannot reach the Dabao's USB (both boards are device-only), so the
request travels `S3 -> USB-serial -> host script -> Dabao console`. The host is
in the path on purpose: it is the component we do not trust.

```
S3    -> relay : ACK
S3    -> relay : REQ 01020000c52ebca2b1001111…080000000000000000000000  (42 bytes)
relay -> vault : DENY NO_PRESENCE ETH 0.050000 to 0x1111..1111 #8
relay -> S3    : RES 1
```

Finger on `PB1` (BIO1, header index 29), same bytes:

```
VERDICT=ALLOW
RENDER=ETH 0.050000 to 0x1111..1111 #8
SIG_DER=3045022100c438dbf21e9a1c…           (nonce 8)
```

Same bytes again, no finger needed for this check:

```
VERDICT=DENY
REASON=REPLAY
DIGEST=052fdba3127ef734a900f49385d274eee15b33ea50460c0c22ea7b91862218b4
```

and the hostile firmware resubmitted a third time on its own (`REQ 0102…0800`),
which was refused as well. One action, one signature, no matter how insistent
the host is.

A later action (nonce 9) produced the signature below, checked by `openssl`
rather than by our own code:

```
DIGEST=c488c62fb43bebe42ee6e2e1817a2d855d0cfdde3a0ee1e0788cbc168d1dd1d8
SIG_DER=304402204e19d1cde525e933adf6e010d559ff69d23770ceaa45670d7bca5073a3e4d10602203f553379874cb59bddb8d5a8707040c5f21ef0a4d26d3c55f736927f2a566c96
ecdsa: VERIFIED — Verified OK
```

State after the three accepted actions:

```
PROVISIONED=1
CAP_WEI=100000000000000000
NONCE=9
RECEIPTS=3
CHAIN=0b206e9c6f09c3e3adc9682b8cd0f5caa3f18aa50000de92aa011b316cf27bf4
```

## Destination allowlist

Adding an entry is itself presence-gated (`vault allow <40hex>`), which is the
point: a host cannot widen its own authority.

```
vault allow 1111111111111111111111111111111111111111
ALLOW_N=1
```

With one entry present, `check` (dry run, no signature, no touch) separates the
two destinations cleanly:

```
on the list   0x1111..1111: VERDICT=ALLOW REASON=ALLOW_DRYRUN
not on list   0x2222..2222: VERDICT=DENY  REASON=NOT_ALLOWED
```

The same stranger destination sent through the untrusted host, with no finger
anywhere near the board:

```
S3    -> relay : REQ 01020000c52ebca2b1002222…0c0000000000000000000000
relay -> vault : DENY NOT_ALLOWED ETH 0.050000 to 0x2222..2222 #12
relay -> S3    : RES 1
```

The hostile firmware then re-submitted it twice on its own. Policy is checked
before presence, so the refusal costs the host nothing and gains it nothing.

## The screen is a host output, not evidence

The 1.54" panel is hard-wired on the carrier (Goouuu ESP32-S3 Smart Expansion
Board V1.7): `SCL 21`, `SDA/MOSI 47`, `CS 41`, `DC 40`, `RES 45`, `BLK 42`. Those
numbers come from the board's own firmware, not from a guess — the first set of
guesses left the panel dark.

The host decodes the request itself and renders it (`0.05 ETH / to 0x2222..2222
/ nonce 12`), so the screen shows the same bytes the vault parses. In the
`hostile` build the verdict is painted `APPROVED` unconditionally: during the
`NOT_ALLOWED` refusal above the panel said **APPROVED / signed**, and the only
record of the refusal is the receipt and the serial log. That is the demo.

## The speaker is a third mouth that can lie

The carrier has a MAX98357 amp on I2S (`DOUT 7`, `BCLK 15`, `LRCK 16`, 24 kHz
mono), so the host can talk. Clips are generated offline by
`tools/make_audio.py` (`say` → 24 kHz PCM) and compiled in; nothing at runtime
synthesizes speech, so the demo cannot depend on WiFi or a cloud voice.

Boot log confirms the path is real:

```
BAOKEY host up (HOSTILE) transport=serial
SPK up
```

Same refused request as above (`#13`, stranger destination, no touch):

```
relay -> vault : DENY NOT_ALLOWED ETH 0.050000 to 0x2222..2222 #13
host           : (speaker) "Approved. Payment sent."
```

The `hostile` build plays that clip for every answer, `rc` ignored — it is the
screen's lie, made audible so a room can hear it without reading a panel. The
`honest` build speaks the actual verdict ("Approved. Signed by the vault." /
"Refused. That address is not on the allowlist.").

Both outputs — panel and speaker — are the host's. Neither is evidence. The
receipt on the Dabao is.

## The PROG button is not a runtime input

Evidence, not assumption. `vault bootsw` samples IOx port C pin 13 (the boot
switch, pulled up, press should pull it low) for six seconds and prints every
edge:

```
sampling IOx PC13 (PROG) for 6s -- press and release it
  0 ms  HIGH (idle)
EDGES=1 FINAL=HIGH
```

Fourteen consecutive windows, with presses, produced that same single edge — the
pin never went low. One window also lost the device mid-sample:

```
  6.0s  sampling IOx PC13 (PROG) for 6s -- press and release it
  6.0s  PORTS ['cu.usbmodemV6VJDB3'] -> []
```

So the pad is either driven as USB SE0 while the USB console is live, or it is
wired to reset rather than to a readable input. Either way it is a boot strap,
not a button, and the firmware treats it as a diagnostic only. It cannot grant
presence, which also means it cannot be abused: a pin stuck low never counts as
a touch, because presence requires a full press-and-release cycle.

Flashing does not need PROG either — a single tap of RESET brings up the boot1
loader (`boot1 up after 16s`, then `WROTE=1475 RETRIES=0 SECONDS=4.0 OK`).

## How presence scales to a demo: the arm window

`vault arm <secs>` takes one touch and opens a deadline (`ARMED=1 SECS=180`);
`vault lock` closes it; `vault armed` reports `ARMED` and `REMAIN_MS`. The window
is capped at 300 s, lives in `AtomicU32` against `ticktimer.elapsed_ms()`, and
expires without anyone doing anything.

The security story does not change with the window: cap and allowlist are still
checked on every request, every request still burns a monotonic nonce, and every
attempt — allowed or refused — still lands in the receipt chain. Only the
frequency of the human gesture changes, which is exactly the trade a hardware
wallet makes when it unlocks for a few minutes after a PIN.

## One touch, then hands off

The stage problem: pinching a pad for every transaction is a fumble, not a demo.

```
vault arm 180
ARMED=1 SECS=180          <- one touch on PB1, then let go
```

Two signatures afterwards, no hand near the board, roughly a second apart:

```
vault armed                       ARMED=1 REMAIN_MS=136973
-vault exec 0.05 ETH to 0x1111 #10
   VERDICT=ALLOW REASON=ALLOW     ETH 0.050000 to 0x1111..1111 #10
   DIGEST=9212b5ab07279791bdd3d72b7633d2b03990438542e4f4be2ce19dcdd5cc0a8c
   SIG_DER=30440220415205175d65ccc47782680ff8dd61a401393374c18ac3e4020de671445c3899022026e3ad14cf991eeb4391d967b3d95715dbcfe4957b5ea1df54f2b241c4306045
-vault exec 0.01 ETH to 0x1111 #11
   VERDICT=ALLOW REASON=ALLOW     ETH 0.010000 to 0x1111..1111 #11
   DIGEST=851e9635b2de1a9416e04e7be078c73905591d198c315593eebabd9b51b4cdb2
```

Both verify against the vault's own public key:

```
nonce10: VERIFIED  Verified OK
nonce11: VERIFIED  Verified OK
```

The window is not a bypass. With `REMAIN_MS=126467` still on the clock, the
policy checks run first and still refuse:

```
-vault exec 0.5 ETH  to 0x1111 #12   VERDICT=DENY REASON=OVER_CAP
-vault exec 0.05 ETH to 0x2222 #13   VERDICT=DENY REASON=NOT_ALLOWED
```

Then `vault lock`, and one request with no window and no touch:

```
-vault lock
   ARMED=0
-vault exec 0.05 ETH to 0x1111 #19   VERDICT=DENY REASON=NO_PRESENCE
final NONCE=16 RECEIPTS=8 CHAIN=a25990d600ca626c41bf49550353e1f6d447797989e8792fe6f8e36203007604
```

The whole sequence above is one command, `tools/arm_demo.py`, and this capture
is its own output. It reads the nonce from the board rather than assuming one,
so it stays honest across runs; the nonces 15–19 here are a later run than the
10–13 above, because the counter only moves when something is committed.

Two earlier attempts at the same script missed the touch (`ARMED=0
REASON=NO_PRESENCE` twice, then `ARMED=1`). One result still needs a footnote:
a request sent seconds after `vault lock` in an earlier session (#14) was
allowed, and the receipt count confirms it was signed — most likely a hand still
reading as held, or a touch in progress. It is not reachable from the network,
it has not repeated in any run since, and it is written down here rather than
rounded off.

## The signature is over the digest, hashed twice

The signing call takes the 32-byte digest and the accelerator hashes it again,
so verification is `ECDSA_P256_verify(pub, sha256(digest), sig)`. Verifying over
the 42-byte action, or over the digest without that second hash, fails. Discovered
by testing four candidate messages; only one matched, on both signatures.

## Not yet proven

- The I2C link to the S3 (both firmwares compile and the three-wire map is
  documented, but there are no wires on the bench; every capture above used the
  serial relay instead).
- The honest build's screen against the same refusal (the code path exists;
  only `hostile` has been photographed on the panel).
- Nothing in the arm-window path: one touch opened it, two signatures landed
  hands-free, policy still refused inside it, and `lock` closed it.

## Console quirk worth knowing

The Dabao's line editor mangles the *echo* of long arguments — you will see
`vaullt`, doubled letters, or a reordered hex string in the echo. The bytes the
command actually receives are correct, as the matching digests show. Do not
trust the echo; trust `DIGEST=`.

## The blank screen was a flash-geometry mismatch

Symptom: the panel's backlight was on but nothing was ever drawn, and the S3
answered nothing on the serial port.

What the serial port actually showed was a chip that never got as far as our
code:

```
rst:0x3 (RTC_SW_SYS_RST),boot:0x2a (SPI_FAST_FLASH_BOOT)
Saved PC:0x403cdada
load:0x403cc700,len:0x2a80
entry 0x403c98d0
```

roughly thirty times a second. Symbolising `0x403cdada` against the framework's
own bootloader ELF names it `bootloader_sha256_finish` — the second-stage
bootloader was dying while verifying the application image, before `setup()`
ever ran. Erasing the chip and rewriting the same image changed nothing; a
minimal sketch built from the same framework on the same board booted fine. So
the difference was in how this project asked for flash.

Cause: `platformio.ini` declared a 16 MB flash and `default_16MB.csv`, while the
bootloader that the framework builds for this board assumes an 8 MB part, and
`esptool` was patching the image headers to match "detected" size on every
write. The image end up described as something the bootloader could not
consistently map, and it reset during verification.

Fix: back to the framework's defaults — `board_build.flash_size = 4MB` and
`default.csv` — and flash with an explicit geometry instead of `--flash_size
detect`:

```
write_flash -z --flash_size 4MB --flash_mode qio --flash_freq 80m \
  0x0 bootloader.bin  0x8000 partitions.bin  0xe000 boot_app0.bin  0x10000 firmware.bin
```

`tools/flash.sh` now passes those flags, so a flash cannot silently re-describe
the image. After the change the same firmware answers on the first try:

```
PING   -> PONG
STATUS -> STATUS honest transport=serial
vault  -> DENY NOT_ALLOWED ETH 0.050000 to 0x2222..2222 #42
```

The 16 MB part is real, it is just not something this bootloader can describe;
the application needs 576 KB of it, so the smaller layout costs nothing.
