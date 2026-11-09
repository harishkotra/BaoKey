#!/usr/bin/env python3
"""Arm the vault and make a noise when the touch lands.

    ./tools/arm.py            # 180 s window
    ./tools/arm.py --secs 60

The board prints nothing when a gesture is accepted, which is awkward on stage.
This waits for the touch, then plays a short chime so you know it took, without
looking at a screen or a terminal.
"""
import argparse
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "host"))
import baokey  # noqa: E402

PORT = os.environ.get("BAOKEY_DAB", "/dev/cu.usbmodemV6VJDB3")


def chime(times=1):
    for _ in range(times):
        subprocess.run(["afplay", "/System/Library/Sounds/Glass.aiff"],
                       capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--secs", type=int, default=180)
    ap.add_argument("--attempts", type=int, default=8)
    a = ap.parse_args()

    fd = baokey.open_port(PORT, 115200)
    os.set_blocking(fd, False)

    def read(secs):
        buf = b""
        end = time.time() + secs
        while time.time() < end:
            try:
                chunk = os.read(fd, 4096)
            except (BlockingIOError, OSError):
                chunk = b""
            if chunk:
                buf += chunk
            else:
                time.sleep(0.05)
        return buf.decode("utf-8", "replace")

    print(f"touch PB1 now -- arming for {a.secs}s", flush=True)
    try:
        for attempt in range(1, a.attempts + 1):
            read(0.3)
            os.write(fd, f"vault arm {a.secs}\r".encode())
            out = read(34)
            if "ARMED=1" in out:
                chime(2)
                print(f"ARMED for {a.secs}s (attempt {attempt}) -- hands off", flush=True)
                return 0
            print(f"  attempt {attempt}: no touch yet", flush=True)
        print("never armed", flush=True)
        chime(1)
        return 1
    finally:
        os.close(fd)


if __name__ == "__main__":
    sys.exit(main())
