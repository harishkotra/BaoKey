# BaoKey wire protocol

Two links, two very different levels of trust.

```
   laptop / browser          ESP32-S3 (untrusted)            Dabao (trusted)
        │                          │                              │
        │  USB serial: ACT <hex>   │   I2C, 100 kHz, addr 0x42    │
        ├─────────────────────────►├─────────────────────────────►│
        │  RES <rc> <text>         │   register window 0x00..0x7f │
        │◄─────────────────────────┤◄─────────────────────────────┤
```

The S3 never sees a key. It carries bytes and paints pixels. Anything it says
about the outcome is a *claim*; the receipt log on the Dabao is the record.

## Action encoding — 42 bytes, signed as-is

| offset | size | field | notes |
|---|---|---|---|
| 0 | 1 | `ver` | must be `1` |
| 1 | 1 | `op` | `1` = login, `2` = ETH transfer |
| 2 | 8 | `value` | wei, little-endian (`op=2` only) |
| 10 | 20 | `to` | destination address |
| 30 | 4 | `nonce` | little-endian, strictly increasing per device |
| 34 | 8 | `ctx` | app context / TLV tail, opaque to the vault |

Digest: `sha256("BAOKEY-ACT-v1\x00" || action_42_bytes)`.
The vault parses those same 42 bytes and renders the text **from the parsed
struct**, so a lying screen cannot change what was signed.

Known-answer test (run `vault selftest` on the board):

```
sha256("BAOKEY-ACT-v1\0" || {ver:1,op:1,value:0,to:0*20,nonce:0,ctx:0*8})
= 19530212d6dcaa4159ba714d8c91392ac6d218bd52ac6fa1f31e70e73003acde
```

## I2C register window (S3 side, target address 0x42)

| reg | size | direction | meaning |
|---|---|---|---|
| `0x00` | 1 | both | `bit0` = request pending (S3 sets, Dabao clears when done) |
| `0x02` | 42 | S3 → Dabao | the action bytes |
| `0x40` | 1 | Dabao → S3 | response code: `0` allow, `1` deny, `2` malformed |
| `0x41` | 1 | Dabao → S3 | text length `n` (≤ 60) |
| `0x42` | n | Dabao → S3 | human string, ASCII |
| `0x7e` | 2 | Dabao → S3 | receipt sequence number, little-endian |

The Dabao polls: read `0x00`, and if bit0 is set it reads the 42 bytes,
decides, writes `0x40..`, then clears `0x00`. A hostile host can write any
bytes it likes into `0x02` — that is exactly what the vault is defending
against, and it is why every field is re-validated on the trusted side.

## Five gates, always in this order

1. `VER`/`OP` fields valid, length exactly 42.
2. Firmware measurement matches the sealed value (`MEASURE` vs `SEALED_MEASURE`).
3. Policy: value ≤ cap, destination in allowlist (RRAM), nonce > last nonce.
4. Physical presence: capacitive touch on the Dabao (host cannot reach it).
5. Sign: P-256 ECDSA. The vault hands the 32-byte digest to the signing
   accelerator, which hashes it again — so the verified message is
   `sha256(digest)`, and a verifier must call `sha256` on the digest bytes,
   not on the 42-byte action. Confirmed against the printed public key for
   nonces 10 and 11 (`Verified OK`). Then append the receipt.

Any failure stops before the keystore is touched, and the refusal itself is
logged with a reason string, so "how many times did an attacker try" is
answerable after the fact.

## Receipts

```
receipt[n] = sha256(receipt[n-1] || digest || sig_der)
```

A truncated log is detectable: the host cannot produce a link that chains to a
receipt it did not see. `vault rcpt` prints the last 8 entries; `rcpt all`
prints the whole chain.
