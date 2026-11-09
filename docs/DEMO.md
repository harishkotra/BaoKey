# The four-minute demo

Everything below runs on hardware that is on the table. No slides.

## 0. Set the scene (30 s)

Two boards, two USB cables, no jumpers. Point at the black ESP32-S3 carrier:

> "This chip has WiFi, Bluetooth, a microphone, a speaker and this screen. It is
> the part an attacker would own. The other board — the bare Dabao — holds the
> key. The only way to approve anything is to touch one pad on the Dabao, and
> the ESP32 cannot reach it."

## 1. Unlock once, then hands off (45 s)

```sh
vault arm 180      # touch PB1 once; the window is 180 seconds
vault armed        # ARMED=1 REMAIN_MS=…
```

> "That single touch unlocks the vault for three minutes and nothing longer. It
> relocks by itself, or I can close it early with `vault lock`. Every approval
> inside the window still needs a fresh nonce and still lands in the receipt
> chain — the human gesture is what changed, not the cryptography."

Keep your hands off the board for the rest of the demo. That is the point.

## 2. It works (60 s)

```sh
./baokey.py mk --op 2 --wei 50000000000000000 --to 0x1111…1111 --nonce 10
python3 host/relay.py send <hex>
```

No touch needed — the window is open. The S3 screen shows `APPROVED · ETH
0.050000 to 0x1111..1111 #10`, and the Dabao prints `VERDICT=ALLOW`, a digest, a
signature, and a receipt hash. Say out loud:

> "The screen didn't decide anything. The vault rendered that line from the same
> bytes it signed — and I never touched the board for that one."

## 3. The host lies (45 s)

Swap the firmware on the S3 (`./tools/flash.sh hostile`, ~12 s). Send a request
to an address that is not on the allowlist. The screen says **APPROVED** and the
speaker says "Approved. Payment sent." — the Dabao prints `DENY NOT_ALLOWED`.

> "The screen and the speaker are compromised and they are telling you it
> worked. The receipt on the other chip says otherwise. Which one would you
> trust at an exchange?"

## 4. Three more refusals (90 s)

```sh
./baokey.py attacks --port /dev/cu.usbmodemXXXX --target dabao
```

- over the spending cap → `OVER_CAP`
- a destination not on the allowlist → `NOT_ALLOWED`
- an old signature replayed → `REPLAY`
- a mangled header → `BAD_VERSION`

Each one is logged with a reason. Then:

```sh
vault rcpt        # the last eight attempts, including the refusals
```

> "Denials are evidence. If someone tries this on my desk and fails, I want the
> attempt on the record."

## 5. Lock it and swap the firmware back (30 s)

```sh
vault lock         # ARMED=0 -- instantly
./tools/flash.sh honest
```

With the window closed, the same request is refused with `NO_PRESENCE` until a
human touches the pad again. Then the honest build shows the real verdict.
Nothing in the vault had to be re-provisioned, because the host was never part
of the trust decision.

## What to say if a judge asks "is this just a hardware wallet?"

> "A hardware wallet trusts its host to describe the transaction and trusts its
> own display to be honest. Here the host is on the record as untrusted: it
> cannot parse, cannot set policy, cannot replay, and cannot fake presence. The
> test isn't the happy path — it's that the hostile build produces no signature
> at all."

## If a judge asks about the arm window

> "A hardware wallet unlocks for a few minutes after a PIN. Same trade here, but
> the gesture is a capacitive pad on the chip that holds the key, the window is
> capped at five minutes, and closing it is instant. Presence is never the same
> thing as authorization: the cap and the allowlist are checked on every single
> request, window or no window."
