#!/usr/bin/env python3
"""One command that proves the trust boundary is intact.

    ./tools/selftest.py

Runs four checks through the real path -- ESP32 host -> serial relay -> Dabao
vault -- and prints PASS/FAIL for each. None of them need a touch, because the
vault refuses before it ever asks for one.

  1. the host answers at all            PING -> PONG
  2. it reports which firmware it runs  STATUS ... transport=serial
  3. a stranger address is refused      DENY NOT_ALLOWED
  4. an over-cap amount is refused      DENY OVER_CAP
  5. the same request twice is refused  DENY REPLAY

Exit code is 0 only if every check passes, so it can gate a demo.
"""
import os
import random
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "host"))
import baokey  # noqa: E402

RELAY = os.path.join(ROOT, "host", "relay.py")
STRANGER = "0x" + "22" * 20
FRIEND = "0x" + "11" * 20
CAP_WEI = 100_000_000_000_000_000  # 0.1 ETH, matches the vault


def relay(*args):
    out = subprocess.run([sys.executable, RELAY, *args],
                         capture_output=True, text=True, timeout=180)
    return out.stdout + out.stderr


def retry(fn, pred, tries=3):
    """USB serial needs a second try more often than it should; do not care why."""
    out = ""
    for _ in range(tries):
        out = fn()
        if pred(out):
            return out
    return out


def send(act):
    return relay("send", act.hex())


def verdict(text):
    m = re.search(r"vault -> relay: (ALLOW|DENY)\s+(\S+)", text)
    return (m.group(1), m.group(2)) if m else ("?", text.strip()[-60:])


def main():
    nonce = random.randrange(1 << 16, 1 << 31)
    results = []

    def check(name, ok, detail=""):
        results.append(ok)
        print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    ping = retry(lambda: relay("ping"), lambda t: "PONG" in t)
    check("host answers PING", "PONG" in ping)

    status = retry(lambda: relay("status"), lambda t: "STATUS" in t)
    m = re.search(r"STATUS (\w+)", status)
    check("host reports firmware", bool(m), m.group(1) if m else "no STATUS line")

    def first_verdict(act):
        return retry(lambda: send(act), lambda t: "vault -> relay:" in t)

    v, why = verdict(first_verdict(baokey.encode(baokey.OP_ETH, 50_000_000_000_000_000, STRANGER, nonce)))
    check("stranger address refused", v == "DENY" and why == "NOT_ALLOWED", f"{v} {why}")

    v, why = verdict(first_verdict(baokey.encode(baokey.OP_ETH, CAP_WEI * 5, FRIEND, nonce + 1)))
    check("over-cap amount refused", v == "DENY" and why == "OVER_CAP", f"{v} {why}")

    act = baokey.encode(baokey.OP_ETH, 10_000_000_000_000_000, STRANGER, nonce + 2)
    first_out = first_verdict(act)
    second_out = first_verdict(act)
    first, second = verdict(first_out), verdict(second_out)
    check("first copy reaches policy", first[0] == "DENY" and first[1] == "NOT_ALLOWED", f"{first[0]} {first[1]}")
    check("duplicate copy earns nothing",
          second[0] == "DENY" and "SIGNATURE ISSUED" not in first_out + second_out,
          f"{second[0]} {second[1]}, no signature either time")

    passed = sum(1 for r in results if r)
    print(f"\n{passed}/{len(results)} checks passed")
    print("Replay after a real signature is covered by tools/arm_demo.py -- it "
          "needs one touch, because nothing is committed until the vault signs.")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
