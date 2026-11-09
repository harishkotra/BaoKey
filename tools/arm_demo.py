#!/usr/bin/env python3
"""Run the whole arm-window demo against the board in one pass.

    ./tools/arm_demo.py            # arm 180 s, two signatures, two refusals, lock
    ./tools/arm_demo.py --secs 90

Talks to the Dabao console directly. First step needs a human touch on PB1
(header pin 29); everything after it runs with nobody at the board.
"""
import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "host"))
import baokey  # noqa: E402

DAB = os.environ.get("BAOKEY_DAB", "/dev/cu.usbmodemV6VJDB3")
ALLOWED = "0x1111111111111111111111111111111111111111"
STRANGER = "0x2222222222222222222222222222222222222222"
WEI_LOW = 50_000_000_000_000_000      # 0.05 ETH
WEI_TINY = 10_000_000_000_000_000     # 0.01 ETH
WEI_OVER = 500_000_000_000_000_000    # 0.5 ETH, above the 0.1 cap


class Board:
    def __init__(self, path):
        self.fd = baokey.open_port(path, 115200)
        os.set_blocking(self.fd, False)

    def read(self, secs):
        buf = b""
        end = time.time() + secs
        while time.time() < end:
            try:
                chunk = os.read(self.fd, 4096)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                buf += chunk
            else:
                time.sleep(0.03)
        return buf.decode("utf-8", "replace")

    def ask(self, line, secs=30.0):
        self.read(0.3)
        os.write(self.fd, (line + "\r").encode())
        buf = ""
        end = time.time() + secs
        while time.time() < end:
            try:
                chunk = os.read(self.fd, 4096)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                buf += chunk.decode("utf-8", "replace")
            else:
                time.sleep(0.05)
        return buf

    def close(self):
        os.close(self.fd)


def fields(text, keys):
    out = []
    for line in text.splitlines():
        line = line.strip()
        if re.match(r"^(%s)=" % "|".join(keys), line):
            out.append(line)
    return out


def mk(nonce, wei, to):
    r = subprocess.run(
        [sys.executable, os.path.join(HERE, "..", "host", "baokey.py"), "mk",
         "--op", "eth", "--wei", str(wei), "--to", to, "--nonce", str(nonce)],
        capture_output=True, text=True)
    for line in (r.stdout or "").splitlines():
        if re.fullmatch(r"[0-9a-f]{84}", line.strip()):
            return line.strip()
    raise SystemExit("mk failed: " + (r.stdout + r.stderr))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=int, default=180)
    ap.add_argument("--port", default=DAB)
    a = ap.parse_args()

    b = Board(a.port)
    try:
        print("state :", " | ".join(fields(b.ask("vault status", 8),
                                           ["NONCE", "RECEIPTS", "CHAIN"])))

        print(f"\n[1] arm {a.secs}s -- touch PB1 once, now")
        armed = None
        for attempt in range(1, 9):
            out = b.ask(f"vault arm {a.secs}", 34)
            got = fields(out, ["ARMED"])
            print(f"    attempt {attempt}: {' '.join(got) or 'no answer'}")
            if any("ARMED=1" in g for g in got):
                armed = True
                break
        if not armed:
            raise SystemExit("never armed -- no touch seen")

        print("\n[2] two signatures, hands off")
        seq = [
            (WEI_LOW, ALLOWED, "allowed target, small"),
            (WEI_TINY, ALLOWED, "allowed target, tiny"),
            (WEI_OVER, ALLOWED, "over the cap"),
            (WEI_LOW, STRANGER, "stranger target"),
        ]
        # nonce comes from the board's own counter, so read it first and walk up
        st = b.ask("vault status", 8)
        m = re.search(r"NONCE=(\d+)", " ".join(st.split()))
        n = int(m.group(1)) + 1 if m else 1
        for wei, to, label in seq:
            out = b.ask(f"vault exec {mk(n, wei, to)}", 36)
            keep = fields(out, ["VERDICT", "REASON", "RENDER"])
            print(f"    #{n} {label:<24} {' '.join(keep)}")
            n += 1

        print("\n[3] lock, then try again with no touch")
        print("   ", " ".join(fields(b.ask("vault lock", 8), ["ARMED"])))
        out = b.ask(f"vault exec {mk(n, WEI_LOW, ALLOWED)}", 40)
        print(f"    #{n} after lock             {' '.join(fields(out, ['VERDICT', 'REASON']))}")

        print("\nfinal :", " | ".join(fields(b.ask("vault status", 8),
                                             ["NONCE", "RECEIPTS", "CHAIN"])))
    finally:
        b.close()


if __name__ == "__main__":
    main()
