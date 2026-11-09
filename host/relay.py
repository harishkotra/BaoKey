#!/usr/bin/env python3
"""relay.py — the dumb pipe between the untrusted host and the vault.

Topology with no wires:

    laptop ──USB──> ESP32-S3   (screen, radio, mic — the untrusted host)
       ^                |
       |             USB serial: REQ <42B hex>
       |                v
       +---------- relay.py ----------> Dabao (USB serial console) —— the vault

The relay moves bytes. It cannot sign, it holds no key, and it is not trusted by
the vault: the vault decides on its own, from the bytes it received. If you
delete this file mid-demo the vault still refuses everything, because the
decision was never here.

Usage:
    python3 relay.py send <42-byte-hex>
    python3 relay.py ping
    python3 relay.py status
"""

import argparse
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import baokey  # noqa: E402

def _find(pattern, fallback):
    """First /dev/cu.* device matching a glob, so nobody guesses port names."""
    import glob

    hits = sorted(glob.glob(pattern))
    return hits[0] if hits else fallback


# The S3 shows up through its UART bridge as usbserial-* (CH340/CP210x) when the
# cable is in the port next to RST/BOOT; the native-USB port gives usbmodem-*.
S3_PORT = os.environ.get("BAOKEY_S3") or _find("/dev/cu.usbserial-*", None) \
    or _find("/dev/cu.usbmodem*", "/dev/cu.usbmodem1101")
DAB_PORT = os.environ.get("BAOKEY_DAB") or _find("/dev/cu.usbmodemV6VJ*", "/dev/cu.usbmodemV6VJDB3")


def read_until(fd, stop_line, secs=20.0, echo=False):
    """Read lines until one starts with stop_line (or the deadline passes)."""
    buf = b""
    end = time.time() + secs
    while time.time() < end:
        try:
            chunk = os.read(fd, 512)
        except (BlockingIOError, OSError):
            chunk = b""
        if chunk:
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                text = line.decode("utf-8", "replace").strip("\r")
                if echo and text:
                    print(f"    | {text}")
                if text.startswith(stop_line):
                    return text
        else:
            time.sleep(0.02)
    return ""


def answer(hexact, s3, dab, verbose=True):
    """One request from the host: host asks, vault answers, host is told."""
    os.write(s3, ("ACT " + hexact + "\r\n").encode())
    req = read_until(s3, "REQ ", secs=5.0, echo=verbose)
    if not req:
        print("  host never forwarded the request")
        return 1
    payload = req[4:].strip()
    if verbose:
        print(f"  host -> relay: {payload[:32]}… ({len(payload)//2} bytes)")

    out = baokey.ask(dab, "vault exec " + payload, secs=25.0)
    kv = baokey.parse_kv(out)
    verdict = kv.get("VERDICT", "?")
    reason = kv.get("REASON", "?")
    render = kv.get("RENDER") or kv.get("STATUS", "")
    sig = kv.get("SIG_DER", "")
    rc = 0 if verdict == "ALLOW" else 1
    text = render if render else reason
    if verbose:
        print(f"  vault -> relay: {verdict} {reason} {render}")
        print(f"  relay -> host: RES {rc} {text}")
    os.write(s3, f"RES {rc} {text}\r".encode())
    if sig:
        print(f"  SIGNATURE ISSUED: {sig[:24]}…")
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["send", "ping", "status"])
    ap.add_argument("hex", nargs="?")
    ap.add_argument("--replays", type=int, default=4,
                    help="how many extra REQ lines to answer (hostile firmware resends)")
    args = ap.parse_args()

    s3 = baokey.open_port(S3_PORT)
    dab = baokey.open_port(DAB_PORT)
    try:
        if args.cmd == "ping":
            os.write(s3, b"PING\r\n")
            print("s3:", read_until(s3, "PONG", secs=3.0) or "(no answer)")
            print("dabao:", baokey.ask(dab, "ver", secs=3.0).strip().splitlines()[-1:])
            return
        if args.cmd == "status":
            os.write(s3, b"STATUS\r\n")
            print("s3:", read_until(s3, "STATUS", secs=3.0) or "(no answer)")
            print(baokey.ask(dab, "vault status", secs=5.0).strip())
            return

        if not args.hex:
            sys.exit("send needs a 42-byte hex action")
        if len(args.hex) != 84:
            sys.exit(f"action must be 84 hex chars (42 bytes), got {len(args.hex)}")

        rc = answer(args.hex, s3, dab)
        # hostile firmware keeps resending the same bytes; answer each so the
        # screen keeps moving, and note what the vault says each time.
        for _ in range(args.replays):
            extra = read_until(s3, "REQ ", secs=2.0, echo=False)
            if not extra:
                break
            payload = extra[4:].strip()
            out = baokey.ask(dab, "vault exec " + payload, secs=10.0)
            kv = baokey.parse_kv(out)
            print(f"  host resent the same bytes -> {kv.get('VERDICT')} {kv.get('REASON')}")
            os.write(s3, f"RES 1 {kv.get('REASON','DENY')}\r".encode())
        print("  done, rc =", rc)
    finally:
        os.close(s3)
        os.close(dab)


if __name__ == "__main__":
    main()
