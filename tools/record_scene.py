#!/usr/bin/env python3
"""Run the demo as a scripted take, so the screen and speaker can be filmed.

Opens both ports once and keeps them open (opening the S3 port mid-take can
reset the ESP32 and blank the panel), then feeds a fixed sequence of requests
with a visible beat and a hold after each one.

    ./tools/record_scene.py                 # refusals only, no touch needed
    ./tools/record_scene.py --sign          # adds one touch -> real signature
    ./tools/record_scene.py --hold 10       # longer pause per beat

Firmware on the S3 decides what the screen says:
    honest   -> REFUSED + "vault said: NOT_ALLOWED"
    hostile  -> APPROVED + "Approved. Payment sent."   (while the vault refuses)
"""

import argparse
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "host"))

import baokey  # noqa: E402
import relay  # noqa: E402

ALLOWED = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
ETH = 10 ** 18


def field(name, dab, secs=6.0):
    kv = baokey.parse_kv(baokey.ask(dab, "vault status", secs=secs))
    return kv.get(name, "")


def resync(fd):
    """Terminate any half-written line the host was in the middle of.

    A killed take or a mid-line RES can leave the host's line buffer holding a
    partial command, so the next thing written is glued onto it and ignored.
    A bare CRLF ends that line first.
    """
    os.write(fd, b"\r\n")
    baokey.read_for(fd, 0.25)


def pump(s3, dab, secs=2.5):
    """Read whatever the host says, answer every REQ in it.

    Hostile firmware resends the same bytes on its own, sometimes merged onto
    the tail of the previous RES line, so match on the payload rather than on
    line starts.
    """
    buf = ""
    end = time.time() + secs
    while time.time() < end:
        buf += baokey.read_for(s3, 0.25)
    answered = 0
    for m in re.finditer(r"REQ\s+([0-9a-fA-F]{84})", buf):
        payload = m.group(1).lower()
        resync(s3)
        kv = baokey.parse_kv(baokey.ask(dab, "vault exec " + payload, secs=3.5))
        print(f"  host resent the same bytes -> {kv.get('VERDICT')} {kv.get('REASON')}")
        os.write(s3, f"RES 1 {kv.get('REASON','DENY')}\r".encode())
        answered += 1
    return answered


def submit(hexact, s3, dab, label, hold, secs=8.0):
    pump(s3, dab, 0.8)                       # drop anything left over from the last beat
    resync(s3)
    print(f"\n=== {label} — watch the screen now ===", flush=True)
    os.write(s3, f"REQ {hexact}\r\n".encode())
    rc = relay.answer(hexact, s3, dab, secs=secs)
    pump(s3, dab, 2.5)
    print(f"  holding the screen for {hold:.0f}s / rc={rc}", flush=True)
    time.sleep(hold)
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--hold", type=float, default=7.0, help="seconds to hold each result")
    ap.add_argument("--sign", action="store_true", help="include one touched signature")
    ap.add_argument("--arm", type=int, default=180, help="arm window in seconds (max 300)")
    args = ap.parse_args()

    s3 = baokey.open_port(relay.S3_PORT)
    dab = baokey.open_port(relay.DAB_PORT)
    relay.settle(s3)
    relay.settle(dab, 0.3)

    script = []                              # (time, label) for the edit
    t0 = time.time()

    def mark(text):
        script.append((time.time() - t0, text))

    try:
        pump(s3, dab, 0.8)                   # clear anything the host queued at boot
        resync(s3)
        os.write(s3, b"STATUS\r\n")
        buf = ""
        for _ in range(5):
            buf += baokey.read_for(s3, 0.8)
            if re.search(r"STATUS\s+(?:honest|hostile)\b", buf):
                break
        m = re.search(r"STATUS\s+(honest|hostile)\b", buf) or re.search(r"\b(honest|hostile)\b", buf)
        fw = m.group(1) if m else "?"
        nonce = int(field("NONCE", dab) or 0)
        receipts = field("RECEIPTS", dab) or "?"
        print(f"host firmware : {fw}")
        print(f"vault nonce   : {nonce}   receipts: {receipts}")
        print("expectation   : " + (
            "screen APPROVES, speaker says 'Approved. Payment sent.', vault refuses"
            if fw == "hostile" else
            "screen says REFUSED and the vault's reason matches"))
        print("\nstarting in 3s — start recording", flush=True)
        time.sleep(3)

        # 1. a destinaton that is not on the allowlist
        mark("beat 1 start")
        n = nonce + 1
        act = baokey.encode(baokey.OP_ETH, 10 ** 16, STRANGER, n)
        print(f"\n[beat 1] 0.01 ETH to {STRANGER[:10]}… (not on the allowlist)")
        submit(act.hex(), s3, dab, "beat 1 · stranger address", args.hold, secs=3.5)
        mark("beat 1 done")

        # 2. a destination that IS allowed, but way over the cap
        mark("beat 2 start")
        n += 1
        act = baokey.encode(baokey.OP_ETH, 5 * ETH, ALLOWED, n)
        print(f"\n[beat 2] 5 ETH to {ALLOWED[:10]}… (cap is 0.1 ETH)")
        submit(act.hex(), s3, dab, "beat 2 · over the cap", args.hold, secs=3.5)
        mark("beat 2 done")

        # 3. optional: one touch, then a signature, then the same bytes again
        if args.sign:
            mark("beat 3 arm")
            print(f"\n[beat 3] arming a {args.arm}s window — TOUCH PB1 NOW", flush=True)
            print("  " + baokey.ask(dab, f"vault arm {args.arm}", secs=args.arm + 5).strip()
                  .replace("\r", "\n  ")[:200])
            mark("beat 3 armed")

            n += 1
            act = baokey.encode(baokey.OP_ETH, 5 * 10 ** 16, ALLOWED, n)
            print(f"\n[beat 3] 0.05 ETH to {ALLOWED[:10]}… inside the window, no touch")
            submit(act.hex(), s3, dab, "beat 3 · signed", args.hold, secs=20.0)
            mark("beat 3 signed")

            print("\n[beat 4] the same bytes again (replay)")
            submit(act.hex(), s3, dab, "beat 4 · replay", args.hold, secs=3.5)
            mark("beat 4 replay")

            print("  " + baokey.ask(dab, "vault lock", secs=6).strip().replace("\r", "\n  "))
            mark("locked")

        print("\n--- take finished ---")
        print(f"nonce {nonce} -> {field('NONCE', dab)}   receipts {receipts} -> {field('RECEIPTS', dab)}")
        print("chain " + field("CHAIN", dab, secs=8.0))
        print("\nedit notes (seconds into the take):")
        for t, label in script:
            print(f"  {t:6.1f}  {label}")
    finally:
        os.close(s3)
        os.close(dab)


if __name__ == "__main__":
    main()
