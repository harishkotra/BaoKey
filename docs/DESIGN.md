# BaoKey — a signing vault whose host is assumed hostile

**One line:** the chip you trust holds the key and the policy; the chip with
WiFi, a microphone and a screen is allowed to *ask* and forbidden to *decide*.

CrossBar Dabao Open Hardware hackathon. Runs on the Baochip-1x `dabao` board
with an ESP32-S3 (EchoKit kit) reused as the untrusted host.

---

## 1. Why this is not another hardware wallet

A normal hardware wallet trusts its host to know what is being signed. The host
sends a digest; the wallet signs the digest; the screen you read is drawn by the
host, or by firmware the host can reflash. The trust boundary is drawn around
the wrong part.

BaoKey moves three things onto the part with no radio:

| Question | Who answers |
|---|---|
| What exactly am I signing? | the Dabao — it parses the 42-byte request itself and renders the text from the same bytes it hashes |
| Am I allowed to sign it? | the Dabao — cap + destination allowlist stored in RRAM |
| Is this a replay? | the Dabao — one-way nonce, refuses anything `<=` the last accepted |
| Is the human really here? | the Dabao — capacitive pad on *this* board, not a button on the host |
| Is the vault itself unmodified? | the Dabao — measures its own `.sealed` section before unsealing the key |
| What did I approve? | the Dabao — a receipt chained into RRAM, `head = H(prev_head || digest || sig)` |

The host gets no vote in any of those rows.

## 2. Trust boundary

```
   laptop (demo attacker)          ESP32-S3 host                Dabao vault
   ─────────────────────           ─────────────                ───────────
   asks for a signature    ──USB──>  WiFi / LCD / speaker  ──I2C──> parse, judge,
   can lie, replay, fuzz             can lie, replay, fuzz            touch, sign,
   can reflash the host              can be reflashed                 log receipt
                                                                     ▲
                                                          WS2812 + captouch
                                                          (host has no wire)
```

The WS2812 and the capacitive pad are wired to the Dabao. A hostile host cannot
paint the LED green or fake a touch. That is the whole argument in one sentence
for a judge.

## 3. The request format

Fixed 42 bytes, parsed on the Dabao. The host never sends a precomputed digest —
a digest from the host would be a display-spoofing attack in one line.

```
off  len  field
  0    1   ver      = 1
  1    1   op       = 1 LOGIN (WebAuthn-style) | 2 ETH transfer
  2    8   value    u64 LE, wei (0 for LOGIN)
 10   20   to       destination address (rp-id hash prefix for LOGIN)
 30    4   nonce    u32 LE, must be > last accepted
 34    8   ctx      challenge tail / display tag
```

`digest = SHA-256("BAOKEY-ACT-v1\0" || the 42 bytes)`.

Rendered text is produced from the *same struct*:

- `ETH 0.100000 to 0xdead..beef #7`
- `LOGIN rp=a1b2c3d4 #7`

So the string on the LCD cannot disagree with the signature, because there is
only one object and both are derived from it.

KAT (locked in `vault selftest`): the all-zero LOGIN action hashes to
`19530212d6dcaa4159ba714d8c91392ac6d218bd52ac6fa1f31e70e73003acde`.

## 4. Wire protocol (Dabao ⇄ ESP32-S3)

I2C, Dabao is **master**, S3 is **target at 0x42**. The Dabao drives the
conversation; the host cannot inject a request the Dabao did not ask for.

| Target reg | Dir | Content |
|---|---|---|
| `0x00` | R/W | `status` — bit0 = request pending; `0x00` + 42 bytes follow at `0x02` |
| `0x40` | R/W | response: `[0]=rc (0 allow, 1 deny, 2 bad request)`, `[1]=len`, `[2..]` text |
| `0x00` write 0 | W | clear the request slot |

Sequence:

1. host fills the 42-byte action into the S3 at `0x02`, sets `status=1`
2. Dabao (running `vault serve 42 <n>`) reads 44 bytes from `0x00`
3. Dabao parses, applies policy, waits for a touch on its own pad, signs
4. Dabao writes the verdict + human text into `0x40`, then clears `0x00`
5. S3 displays the Dabao's text verbatim and forwards the same text to the host

A hostile host can skip step 5 entirely. It still cannot reach step 3: the
touch has to happen on the Dabao, and the LED that tells the human "signed" is
not on the host's bus.

## 5. Refusals (the demo)

| # | Attack | Dabao says |
|---|---|---|
| 1 | replay an already-signed request | `REASON=REPLAY` |
| 2 | move more than the cap | `REASON=OVER_CAP` |
| 3 | send to a destination not on the allowlist | `REASON=NOT_ALLOWED` |
| 4 | run a modified image on the vault | `REASON=MEASUREMENT_MISMATCH` |
| 5 | ask without touching the pad | `REASON=NO_PRESENCE` |
| 6 | hostile host hides the prompt on its LCD | signature never happens; the Dabao's LED stays red |

## 6. What is measured, and what is not

Measured: the 96-byte `.sealed` blob (policy text + sentinel) in the running
image. One byte changed → different digest → `sealed sign` and `vault exec`
both refuse.

Not measured, stated plainly: the kernel, the rest of the application, and RAM
after load. BaoKey is a tamper-*evident* design, not a formally verified one.
The store of record is the receipt chain in RRAM: an attacker who rewrites the
policy must also produce a chain head that matches the receipts already handed
out, which they cannot do without the device key.

## 7. Storage map (RRAM keystore slots)

| Slot | Owner | Content |
|---|---|---|
| 1400–1403 | `sealed` | state, sealed measurement, device seed, sign counter |
| 1410 | `vault` | policy: magic `BKYPOL01` \| cap u64 \| allow count |
| 1411 | `vault` | last accepted nonce (u32) |
| 1412 | `vault` | receipt chain head (32 B) |
| 1413 | `vault` | receipts issued (u32) |
| 1414 | `vault` | last receipt (32 B) |
| 1415 | `vault` | `BAOKEY01` when provisioned |
| 1420–1423 | `vault` | allowlist, one 20-byte address per slot |

## 8. Console surface

```
vault status
vault init                      provision (cap 0.1 ETH, empty allowlist)
vault cap <wei>                 needs touch
vault allow <40hex>             needs touch
vault denyall                   needs touch
vault check <84hex>             policy only, no signature
vault exec  <84hex>             policy + touch + signature + receipt
vault serve 42 600              I2C loop: serve 600 polling rounds
vault rcpt                      receipts issued, chain head, last receipt
vault selftest                  encoding KAT + policy table
```

## 9. Honest limits (write these in the submission)

- The allowlist holds 4 destinations; that is a demo constraint, not a design one.
- The receipt log keeps the chain head, count and last receipt, not every record.
  Full append-only history needs raw RRAM access, which is the next milestone.
- `vault serve` is a console-driven loop, not a background daemon. A judge sees
  it as a command; a product would run it from a service.
- The I2C link is unauthenticated by construction — it does not need to be,
  because the Dabao treats every byte from it as hostile input.
