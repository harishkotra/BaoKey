#!/usr/bin/env python3
"""BaoKey host client — talks to the untrusted ESP32-S3, or straight to the vault.

Verification deliberately shells out to `openssl dgst -sha256 -verify` so that
"the signature checks out" is not a claim made by the same code that produced
it. No third-party Python packages are required.

  ./baokey.py mk --op eth --value 0.05 --to 0x1111... --nonce 1
  ./baokey.py s3   --port /dev/cu.usbserial-XXXX --act <84hex>
  ./baokey.py dabao --port /dev/cu.usbmodemV6VJDB3 exec --act <84hex>
  ./baokey.py verify --pubkey <hex> --digest <hex> --sig <hex> [--prev <hex> --receipt <hex>]
  ./baokey.py attacks --port <port> --target {s3,dabao}
"""

import argparse
import hashlib
import os
import select
import subprocess
import sys
import tempfile
import termios
import time
from decimal import Decimal

ACT_PREFIX = b"BAOKEY-ACT-v1\x00"
ACT_LEN = 42
OP_LOGIN, OP_ETH = 1, 2
WEI = 10**18


# ---------------------------------------------------------------- encoding ---

def encode(op, value_wei, to_hex, nonce, ctx_hex="0000000000000000"):
    to = bytes.fromhex(to_hex.replace("0x", "").rjust(40, "0"))
    assert len(to) == 20, "destination must be 20 bytes"
    ctx = bytes.fromhex(ctx_hex)
    assert len(ctx) == 8, "ctx must be 8 bytes"
    b = bytes([1, op]) + value_wei.to_bytes(8, "little") + to
    b += nonce.to_bytes(4, "little") + ctx
    assert len(b) == ACT_LEN
    return b


def digest_of(act):
    return hashlib.sha256(ACT_PREFIX + act).digest()


def render(act):
    op, value = act[1], int.from_bytes(act[2:10], "little")
    to = act[10:30]
    nonce = int.from_bytes(act[30:34], "little")
    if op == OP_ETH:
        whole, frac = divmod(value, WEI)
        return f"ETH {whole}.{frac // 10**12:06d} to 0x{to[:2].hex()}..{to[18:20].hex()} #{nonce}"
    if op == OP_LOGIN:
        return f"LOGIN rp={act[34:38].hex()} #{nonce}"
    return f"OP{op} #{nonce}"


# ------------------------------------------------------------------ serial ---

def open_port(path, baud=115200):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    a = termios.tcgetattr(fd)
    a[0] = 0
    a[1] = 0
    a[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    a[3] = 0
    speed = {9600: termios.B9600, 57600: termios.B57600, 115200: termios.B115200,
             230400: termios.B230400}[baud]
    a[4] = speed   # ispeed -- without this the OS keeps the tty's old rate and
    a[5] = speed   # ospeed    every read comes back empty on a 115200 device
    a[6][termios.VMIN] = 0
    a[6][termios.VTIME] = 0
    termios.tcsetattr(fd, termios.TCSANOW, a)
    termios.tcflush(fd, termios.TCIOFLUSH)
    return fd


def read_for(fd, secs):
    out = b""
    t0 = time.time()
    while time.time() - t0 < secs:
        r, _, _ = select.select([fd], [], [], 0.1)
        if r:
            try:
                d = os.read(fd, 8192)
            except OSError:
                break
            if not d:
                break
            out += d
    return out.decode("utf-8", "replace")


def ask(fd, line, secs=8.0, until="OK\n"):
    os.write(fd, (line + "\r").encode())
    end = time.time() + secs
    buf = ""
    while time.time() < end:
        buf += read_for(fd, 0.3)
        if until and until in buf:
            break
    return buf


# ------------------------------------------------------------------ verify ---

def _spki_from_raw(pub_hex):
    raw = bytes.fromhex(pub_hex.replace("0x", ""))
    if len(raw) == 65 and raw[0] == 4:
        point = raw
    elif len(raw) == 64:
        point = b"\x04" + raw
    else:
        raise ValueError("public key must be 64 or 65 bytes")
    # SubjectPublicKeyInfo for id-ecPublicKey / prime256v1, fixed prefix
    prefix = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")
    return prefix + point


def verify(pub_hex, digest_hex, sig_hex):
    """openssl verify of ECDSA-P256 over SHA-256(digest bytes)."""
    with tempfile.TemporaryDirectory() as td:
        pem = os.path.join(td, "pub.der")
        sig = os.path.join(td, "sig.der")
        msg = os.path.join(td, "msg.bin")
        open(pem, "wb").write(_spki_from_raw(pub_hex))
        open(sig, "wb").write(bytes.fromhex(sig_hex))
        open(msg, "wb").write(bytes.fromhex(digest_hex))
        r = subprocess.run(
            ["openssl", "dgst", "-sha256", "-keyform", "DER", "-verify", pem,
             "-signature", sig, msg],
            capture_output=True, text=True)
        return r.returncode == 0, (r.stdout + r.stderr).strip()


def receipt_of(prev, digest, sig_der):
    return hashlib.sha256(prev + digest + sig_der).digest()


# ------------------------------------------------------------------- parse ---

def parse_kv(text):
    kv = {}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            if k.isupper() or k.replace("_", "").isupper():
                kv[k.strip()] = v.strip()
    return kv


def send_and_parse(port, act, target):
    fd = open_port(port)
    try:
        if target == "s3":
            os.write(fd, ("ACT " + act.hex() + "\n").encode())
            buf = read_for(fd, 25)
            for line in buf.splitlines():
                if line.startswith("RES "):
                    _, rc, txt = line.split(" ", 2)
                    return {"VERDICT": "ALLOW" if rc == "0" else "DENY",
                            "REASON": "ALLOW" if rc == "0" else txt,
                            "RENDER": txt}, buf
            return {"VERDICT": "TIMEOUT", "REASON": "no_response", "RENDER": render(act)}, buf
        cmd = "vault exec " + act.hex()
        buf = ask(fd, cmd, secs=40)
        return parse_kv(buf), buf
    finally:
        os.close(fd)


# -------------------------------------------------------------------- main ---

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    m = sub.add_parser("mk")
    m.add_argument("--op", choices=["eth", "login"], default="eth")
    m.add_argument("--value", default="0", help="ETH amount, e.g. 0.05")
    m.add_argument("--wei", default=None, help="exact amount in wei (overrides --value)")
    m.add_argument("--to", default="0x" + "11" * 20)
    m.add_argument("--nonce", type=int, default=1)
    m.add_argument("--ctx", default="0000000000000000")

    s = sub.add_parser("s3")
    s.add_argument("--port", required=True)
    s.add_argument("--act", required=True)

    d = sub.add_parser("dabao")
    d.add_argument("--port", required=True)
    d.add_argument("what", choices=["exec", "check", "status", "rcpt", "selftest", "init"])
    d.add_argument("--act", default="")

    v = sub.add_parser("verify")
    v.add_argument("--pubkey", required=True)
    v.add_argument("--digest", required=True)
    v.add_argument("--sig", required=True)
    v.add_argument("--prev", default="00" * 32)
    v.add_argument("--receipt", default=None)

    a = sub.add_parser("attacks")
    a.add_argument("--port", required=True)
    a.add_argument("--target", choices=["s3", "dabao"], default="dabao")
    a.add_argument("--nonce", type=int, default=100)

    args = ap.parse_args()

    if args.cmd == "mk":
        op = OP_ETH if args.op == "eth" else OP_LOGIN
        if args.op == "eth":
            value = int(args.wei) if args.wei else int(Decimal(args.value) * WEI)
        else:
            value = 0
        act = encode(op, value, args.to, args.nonce, args.ctx)
        print(act.hex())
        print("#", render(act), "digest", digest_of(act).hex(), file=sys.stderr)

    elif args.cmd == "s3":
        act = bytes.fromhex(args.act)
        kv, raw = send_and_parse(args.port, act, "s3")
        print(raw.strip())
        print("->", kv.get("VERDICT"), kv.get("REASON"), "|", kv.get("RENDER"))

    elif args.cmd == "dabao":
        fd = open_port(args.port)
        try:
            line = f"vault {args.what}"
            if args.act:
                line += " " + args.act
            out = ask(fd, line, secs=45 if args.what == "exec" else 6)
        finally:
            os.close(fd)
        print(out.strip())
        kv = parse_kv(out)
        if args.what in ("exec", "check") and kv.get("SIG_DER"):
            ok, why = verify(kv["PUBKEY"], kv["DIGEST"], kv["SIG_DER"])
            print(f"# openssl: {'VERIFIED' if ok else 'FAILED'} ({why})")

    elif args.cmd == "verify":
        ok, why = verify(args.pubkey, args.digest, args.sig)
        print(f"ecdsa: {'VERIFIED' if ok else 'FAILED'} — {why}")
        if args.receipt:
            prev = bytes.fromhex(args.prev)
            calc = receipt_of(prev, bytes.fromhex(args.digest), bytes.fromhex(args.sig))
            hit = calc.hex() == args.receipt.lower()
            print(f"receipt chain: {'MATCH' if hit else 'MISMATCH'} ({calc.hex()})")
        sys.exit(0 if ok else 1)

    elif args.cmd == "attacks":
        run_attacks(args)


def run_attacks(args):
    n = args.nonce
    dest = "11" * 20
    cases = [
        ("over-cap", encode(OP_ETH, 5 * WEI, dest, n + 1), "OVER_CAP"),
        ("not-allowlisted", encode(OP_ETH, 1, "22" * 20, n + 2), "NOT_ALLOWED"),
        ("replay-old-nonce", encode(OP_ETH, 1, dest, 1), "REPLAY"),
        ("bad-version", bytes([9, 2]) + bytes(40), "BAD_VERSION"),
    ]
    print(f"{'attack':22} {'verdict':8} {'dabao said':22} {'render'}")
    print("-" * 96)
    for name, act, expect in cases:
        kv, _ = send_and_parse(args.port, act, args.target)
        got = kv.get("REASON", "?")
        mark = "ok " if got == expect else "?? "
        print(f"{mark}{name:20} {kv.get('VERDICT','?'):8} {got:22} {kv.get('RENDER','')}")


if __name__ == "__main__":
    main()
