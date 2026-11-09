//! BAOKEY — a signing vault that assumes its host is hostile.
//!
//! The host (an ESP32-S3 with WiFi, a microphone and a screen) is allowed to
//! *ask*. It is not allowed to *decide*. Everything below exists so that the
//! only place a signature can be produced is this chip, after this chip has:
//!
//!   1. parsed the request itself (never trusting a digest computed off-chip),
//!   2. checked its own running measurement against the sealed one,
//!   3. applied a spend/destination policy held in RRAM,
//!   4. rejected a replayed nonce,
//!   5. seen a physical touch on *this* board's capacitive pad.
//!
//! The rendered string that the host displays is produced from the same bytes
//! that are hashed and signed, so a lying screen cannot make the signature say
//! something else. The WS2812 on this board is the one indicator the host has
//! no wire to.

use core::fmt::Write as _;
use std::time::Duration;

use bao1x_api::{I2cApi, I2cResult};
use bao1x_hal::i2c::I2c;
use keystore::Keystore;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};

use crate::cmds::sealed::measure;
use crate::{CommonEnv, ShellCmdApi};

fn hex(bytes: &[u8]) -> String {
    const D: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(D[(b >> 4) as usize] as char);
        s.push(D[(b & 0x0f) as usize] as char);
    }
    s
}

fn unhex<const N: usize>(s: &str, n: usize) -> Option<[u8; N]> {
    let b = s.as_bytes();
    if b.len() != n * 2 || N != n {
        return None;
    }
    let mut out = [0u8; N];
    for i in 0..N {
        let hi = (b[2 * i] as char).to_digit(16)?;
        let lo = (b[2 * i + 1] as char).to_digit(16)?;
        out[i] = ((hi << 4) | lo) as u8;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Storage. Slots 1400..1404 belong to SEALED (state, measure, seed, counter).
// BAOKEY starts at 1410 so the two commands never collide.
// ---------------------------------------------------------------------------

const SLOT_POLICY: usize = 1410; // magic|cap|allow_count
const SLOT_NONCE: usize = 1411; // last accepted nonce, u32 LE
const SLOT_CHAIN: usize = 1412; // receipt chain head, 32 B
const SLOT_COUNT: usize = 1413; // receipts issued, u32 LE
const SLOT_LAST: usize = 1414; // last receipt, 32 B
const SLOT_STATE: usize = 1415; // BAOKEY01 when provisioned
const SLOT_ALLOW: usize = 1420; // 1420..1424, one 20-byte address each
const SLOT_SEED: usize = 1402; // the device key minted by `sealed enroll`

const MAX_ALLOW: usize = 4;

const fn pad32(s: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < s.len() && i < 32 {
        out[i] = s[i];
        i += 1;
    }
    out
}
const MAGIC_READY: [u8; 32] = pad32(b"BAOKEY01");
const MAGIC_POLICY: [u8; 8] = *b"BKYPOL01";

// ---------------------------------------------------------------------------
// The canonical action. 42 bytes, fixed layout, version byte first.
//
//   ver 1 | op 1 | value 8 LE | to 20 | nonce 4 LE | ctx 8      = 42
//
// Both sides of the wire see the same 42 bytes; the digest is derived here and
// only here.
// ---------------------------------------------------------------------------

pub const ACT_LEN: usize = 42;
const ACT_PREFIX: &[u8] = b"BAOKEY-ACT-v1\x00";

#[derive(Clone, Copy)]
pub struct Action {
    pub ver: u8,
    pub op: u8,
    pub value: u64,
    pub to: [u8; 20],
    pub nonce: u32,
    pub ctx: [u8; 8],
}

impl Action {
    pub fn parse(b: &[u8]) -> Result<Action, &'static str> {
        if b.len() != ACT_LEN {
            return Err("BAD_LEN");
        }
        let ver = b[0];
        if ver != 1 {
            return Err("BAD_VERSION");
        }
        let op = b[1];
        if op != 1 && op != 2 {
            return Err("BAD_OP");
        }
        let mut value = [0u8; 8];
        value.copy_from_slice(&b[2..10]);
        let mut to = [0u8; 20];
        to.copy_from_slice(&b[10..30]);
        let mut nonce = [0u8; 4];
        nonce.copy_from_slice(&b[30..34]);
        let mut ctx = [0u8; 8];
        ctx.copy_from_slice(&b[34..42]);
        Ok(Action {
            ver,
            op,
            value: u64::from_le_bytes(value),
            to,
            nonce: u32::from_le_bytes(nonce),
            ctx,
        })
    }

    pub fn encode(&self) -> [u8; ACT_LEN] {
        let mut b = [0u8; ACT_LEN];
        b[0] = self.ver;
        b[1] = self.op;
        b[2..10].copy_from_slice(&self.value.to_le_bytes());
        b[10..30].copy_from_slice(&self.to);
        b[30..34].copy_from_slice(&self.nonce.to_le_bytes());
        b[34..42].copy_from_slice(&self.ctx);
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(ACT_PREFIX);
        h.update(self.encode());
        let d = h.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&d);
        out
    }

    /// The bytes the human is asked to approve. Derived from the same struct
    /// that is hashed, so the screen and the signature cannot diverge.
    pub fn render(&self) -> String {
        let mut s = String::new();
        match self.op {
            1 => {
                write!(s, "LOGIN rp=").ok();
                for b in &self.ctx[..4] {
                    write!(s, "{:02x}", b).ok();
                }
            }
            2 => {
                let unit = 1_000_000_000_000_000_000u64;
                let whole = self.value / unit;
                let frac = (self.value % unit) / 1_000_000_000_000u64;
                write!(s, "ETH {}.{:06} to 0x", whole, frac).ok();
                for b in &self.to[..2] {
                    write!(s, "{:02x}", b).ok();
                }
                write!(s, "..").ok();
                for b in &self.to[18..20] {
                    write!(s, "{:02x}", b).ok();
                }
            }
            _ => {
                write!(s, "OP{}", self.op).ok();
            }
        }
        write!(s, " #{}", self.nonce).ok();
        s
    }

    fn is_allowed_dest(&self, allow: &[[u8; 20]]) -> bool {
        allow.iter().any(|a| *a == self.to)
    }
}

// ---------------------------------------------------------------------------
// Policy in RRAM.
// ---------------------------------------------------------------------------

struct Policy {
    cap: u64,
    allow: Vec<[u8; 20]>,
}

fn load_policy(ks: &Keystore) -> Option<Policy> {
    let raw = ks.read_app_key(SLOT_POLICY).ok()?;
    if raw[..8] != MAGIC_POLICY {
        return None;
    }
    let mut capb = [0u8; 8];
    capb.copy_from_slice(&raw[8..16]);
    let n = raw[16] as usize;
    let mut allow = Vec::new();
    for i in 0..n.min(MAX_ALLOW) {
        if let Ok(a) = ks.read_app_key(SLOT_ALLOW + i) {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&a[..20]);
            if addr != [0u8; 20] {
                allow.push(addr);
            }
        }
    }
    Some(Policy {
        cap: u64::from_le_bytes(capb),
        allow,
    })
}

fn store_policy(ks: &Keystore, p: &Policy) -> Result<(), &'static str> {
    let mut raw = [0u8; 32];
    raw[..8].copy_from_slice(&MAGIC_POLICY);
    raw[8..16].copy_from_slice(&p.cap.to_le_bytes());
    raw[16] = p.allow.len() as u8;
    ks.write_app_key(SLOT_POLICY, &raw).map_err(|_| "STORE_FAILED")?;
    for (i, a) in p.allow.iter().enumerate().take(MAX_ALLOW) {
        let mut slot = [0u8; 32];
        slot[..20].copy_from_slice(a);
        ks.write_app_key(SLOT_ALLOW + i, &slot)
            .map_err(|_| "STORE_FAILED")?;
    }
    // Blank the tail so a shrinking allowlist is really gone.
    for i in p.allow.len()..MAX_ALLOW {
        ks.write_app_key(SLOT_ALLOW + i, &[0u8; 32])
            .map_err(|_| "STORE_FAILED")?;
    }
    Ok(())
}

fn read_u32(ks: &Keystore, slot: usize) -> u32 {
    ks.read_app_key(slot)
        .map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
        .unwrap_or(0)
}

fn write_u32(ks: &Keystore, slot: usize, v: u32) {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&v.to_le_bytes());
    ks.write_app_key(slot, &b).ok();
}

// ---------------------------------------------------------------------------
// Indicators. These are wired to this chip, not to the host.
// ---------------------------------------------------------------------------

fn led(rgb: (u8, u8, u8)) {
    if let Ok(mut strip) =
        bio_lib::ws2812::Ws2812::new(bio_lib::ws2812::LedVariant::B, arbitrary_int::u5::new(5), None)
    {
        let px = bio_lib::ws2812::rgb_to_u32(rgb.0, rgb.1, rgb.2);
        let frame = [px; 6];
        strip.send(&frame);
    }
}

fn idle() {
    led((0, 0, 8));
}

fn allow_led() {
    led((0, 40, 0));
    std::thread::sleep(Duration::from_millis(400));
    idle();
}

fn deny_led() {
    led((60, 0, 0));
    std::thread::sleep(Duration::from_millis(900));
    idle();
}

/// Physical presence, measured on this board's capacitive pad (BIO pin 1).
fn presence(timeout_ms: u64) -> bool {
    match bio_lib::captouch::Captouch::new(arbitrary_int::u5::new(1), None) {
        Ok(mut cap) => {
            if cap.calibrate(Some(Duration::from_millis(300))).is_err() {
                return false;
            }
            cap.wait_touch_and_release(Some(Duration::from_millis(timeout_ms)))
                .is_ok()
        }
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// The gate. One function, used by both the console and the wire.
// ---------------------------------------------------------------------------

pub struct Outcome {
    pub allowed: bool,
    pub reason: &'static str,
    pub render: String,
    pub digest: [u8; 32],
    pub sig_der: Vec<u8>,
    pub pubkey: Vec<u8>,
    pub receipt: [u8; 32],
    pub seq: u32,
}

impl VaultCmd {
    fn gate(
        &self,
        env: &mut CommonEnv,
        act: &Action,
        want_presence: bool,
        dry_run: bool,
    ) -> Outcome {
        let mut out = Outcome {
            allowed: false,
            reason: "UNKNOWN",
            render: act.render(),
            digest: act.digest(),
            sig_der: Vec::new(),
            pubkey: Vec::new(),
            receipt: [0u8; 32],
            seq: 0,
        };

        // 1. provisioned?
        if self.ks.read_app_key(SLOT_STATE).unwrap_or([0u8; 32]) != MAGIC_READY {
            out.reason = "NOT_PROVISIONED";
            return out;
        }
        // 2. is this chip running the image that was sealed?
        let sealed = self.ks.read_app_key(1401).ok();
        let current = measure();
        match (&sealed, &current) {
            (Some(s), Ok(c)) if s == c => {}
            (_, Err(_)) => {
                out.reason = "MEASUREMENT_UNAVAILABLE";
                return out;
            }
            _ => {
                out.reason = "MEASUREMENT_MISMATCH";
                return out;
            }
        }
        // 3. replay?
        let last = read_u32(&self.ks, SLOT_NONCE);
        if act.nonce <= last {
            out.reason = "REPLAY";
            return out;
        }
        // 4. policy?
        let pol = match load_policy(&self.ks) {
            Some(p) => p,
            None => {
                out.reason = "POLICY_NOT_SET";
                return out;
            }
        };
        if act.op == 2 {
            if act.value > pol.cap {
                out.reason = "OVER_CAP";
                return out;
            }
            if !pol.allow.is_empty() && !act.is_allowed_dest(&pol.allow) {
                out.reason = "NOT_ALLOWED";
                return out;
            }
        }
        // 5. a human, on this chip.
        if dry_run {
            out.allowed = true;
            out.reason = "ALLOW_DRYRUN";
            return out;
        }
        if want_presence && !presence(15_000) {
            out.reason = "NO_PRESENCE";
            return out;
        }
        // 6. sign.
        let seed = match self.ks.read_app_key(SLOT_SEED) {
            Ok(s) => s,
            Err(_) => {
                out.reason = "NO_KEY";
                return out;
            }
        };
        let sk = match SigningKey::from_bytes(&seed) {
            Ok(k) => k,
            Err(_) => {
                out.reason = "BAD_KEY";
                return out;
            }
        };
        let sig: Signature = sk.sign(&out.digest);
        out.sig_der = sig.to_der().as_bytes().to_vec();
        out.pubkey = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();

        // 7. receipt chain: head = H(prev_head || digest || sig)
        let mut head = self.ks.read_app_key(SLOT_CHAIN).unwrap_or([0u8; 32]);
        let mut h = Sha256::new();
        h.update(head);
        h.update(out.digest);
        h.update(&out.sig_der);
        let r = h.finalize();
        out.receipt.copy_from_slice(&r);
        head.copy_from_slice(&r);

        let seq = last.wrapping_add(1);
        write_u32(&self.ks, SLOT_NONCE, act.nonce);
        write_u32(&self.ks, SLOT_COUNT, read_u32(&self.ks, SLOT_COUNT).wrapping_add(1));
        self.ks.write_app_key(SLOT_CHAIN, &head).ok();
        self.ks.write_app_key(SLOT_LAST, &out.receipt).ok();

        out.allowed = true;
        out.reason = "ALLOW";
        out.seq = seq;
        let _ = env;
        out
    }
}

// ---------------------------------------------------------------------------
// Command surface
// ---------------------------------------------------------------------------

pub struct VaultCmd {
    ks: Keystore,
}

impl VaultCmd {
    pub fn new(xns: &xous_names::XousNames) -> Self {
        VaultCmd {
            ks: Keystore::new(xns),
        }
    }

    fn fmt_outcome(ret: &mut String, o: &Outcome) {
        write!(
            ret,
            "VERDICT={}\nREASON={}\nRENDER={}\n",
            if o.allowed { "ALLOW" } else { "DENY" },
            o.reason,
            o.render
        )
        .ok();
        write!(ret, "DIGEST={}\n", hex(&o.digest)).ok();
        if o.allowed {
            write!(ret, "SIG_DER={}\n", hex(&o.sig_der)).ok();
            write!(ret, "PUBKEY={}\n", hex(&o.pubkey)).ok();
            write!(ret, "RCPT={}\n", hex(&o.receipt)).ok();
            write!(ret, "SEQ={}\n", o.seq).ok();
        }
        ret.push_str("OK\n");
    }

    fn help(&self) -> String {
        let mut s = String::new();
        writeln!(s, "vault <cmd>:").ok();
        writeln!(s, "  status                  policy, nonce, receipt chain").ok();
        writeln!(s, "  init                    provision the vault (no presence)").ok();
        writeln!(s, "  cap <wei>               set the spend cap   (needs touch)").ok();
        writeln!(s, "  allow <40hex>           allowlist a 20-byte destination (needs touch)").ok();
        writeln!(s, "  denyall                 empty the allowlist (needs touch)").ok();
        writeln!(s, "  check <84hex>           policy decision only, no signature").ok();
        writeln!(s, "  exec <84hex>            full path: policy + touch + signature + receipt").ok();
        writeln!(s, "  serve <addr_hex> <n>    poll an I2C target for requests").ok();
        writeln!(s, "  rcpt                    last receipt").ok();
        writeln!(s, "  selftest                canonical-encoding KAT + policy table").ok();
        s
    }
}

impl<'a> ShellCmdApi<'a> for VaultCmd {
    cmd_api!(vault);

    fn process(&mut self, args: String, env: &mut CommonEnv) -> Result<Option<String>, xous::Error> {
        let mut ret = String::new();
        let mut tokens = args.split_whitespace();
        let sub = tokens.next().unwrap_or("");

        match sub {
            "status" => {
                let ready = self.ks.read_app_key(SLOT_STATE).unwrap_or([0u8; 32]) == MAGIC_READY;
                writeln!(ret, "BAOKEY v1").ok();
                writeln!(ret, "PROVISIONED={}", if ready { 1 } else { 0 }).ok();
                match load_policy(&self.ks) {
                    Some(p) => {
                        writeln!(ret, "CAP_WEI={}", p.cap).ok();
                        writeln!(ret, "ALLOW_N={}", p.allow.len()).ok();
                        for (i, a) in p.allow.iter().enumerate() {
                            writeln!(ret, "ALLOW_{}=0x{}", i, hex(a)).ok();
                        }
                    }
                    None => {
                        writeln!(ret, "CAP_WEI=0").ok();
                        writeln!(ret, "ALLOW_N=0").ok();
                    }
                }
                writeln!(ret, "NONCE={}", read_u32(&self.ks, SLOT_NONCE)).ok();
                writeln!(ret, "RECEIPTS={}", read_u32(&self.ks, SLOT_COUNT)).ok();
                writeln!(ret, "CHAIN={}", hex(&self.ks.read_app_key(SLOT_CHAIN).unwrap_or([0u8; 32]))).ok();
                match measure() {
                    Ok(c) => writeln!(ret, "MEASURE={}", hex(&c)).ok(),
                    Err(e) => writeln!(ret, "MEASURE=ERR_{}", e).ok(),
                };
                if let Ok(sd) = self.ks.read_app_key(SLOT_SEED) {
                    if let Ok(sk) = SigningKey::from_bytes(&sd) {
                        writeln!(ret, "PUBKEY={}", hex(sk.verifying_key().to_encoded_point(false).as_bytes())).ok();
                    }
                }
                ret.push_str("OK\n");
            }
            "init" => {
                let p = Policy { cap: 100_000_000_000_000_000, allow: Vec::new() };
                if store_policy(&self.ks, &p).is_err() {
                    writeln!(ret, "ERR POLICY_STORE_FAILED").ok();
                    return Ok(Some(ret));
                }
                write_u32(&self.ks, SLOT_NONCE, 0);
                write_u32(&self.ks, SLOT_COUNT, 0);
                self.ks.write_app_key(SLOT_CHAIN, &[0u8; 32]).ok();
                self.ks.write_app_key(SLOT_LAST, &[0u8; 32]).ok();
                self.ks.write_app_key(SLOT_STATE, &MAGIC_READY).ok();
                writeln!(ret, "PROVISIONED=1").ok();
                writeln!(ret, "CAP_WEI={}", p.cap).ok();
                ret.push_str("OK\n");
            }
            "cap" => {
                let raw = match tokens.next().and_then(|t| t.parse::<u64>().ok()) {
                    Some(v) => v,
                    None => {
                        writeln!(ret, "ERR usage: vault cap <wei>").ok();
                        return Ok(Some(ret));
                    }
                };
                if measure().is_err() || self.ks.read_app_key(1401).ok() != measure().ok() {
                    writeln!(ret, "VERDICT=DENY\nREASON=MEASUREMENT_MISMATCH").ok();
                    deny_led();
                    ret.push_str("OK\n");
                    return Ok(Some(ret));
                }
                if !presence(15_000) {
                    writeln!(ret, "VERDICT=DENY\nREASON=NO_PRESENCE").ok();
                    deny_led();
                    ret.push_str("OK\n");
                    return Ok(Some(ret));
                }
                let mut p = load_policy(&self.ks).unwrap_or(Policy { cap: 0, allow: Vec::new() });
                p.cap = raw;
                store_policy(&self.ks, &p).ok();
                writeln!(ret, "CAP_WEI={}", raw).ok();
                allow_led();
                ret.push_str("OK\n");
            }
            "allow" => {
                let a = match tokens.next().and_then(|t| unhex(t, 20)) {
                    Some(v) => v,
                    None => {
                        writeln!(ret, "ERR usage: vault allow <40hex>").ok();
                        return Ok(Some(ret));
                    }
                };
                if !presence(15_000) {
                    writeln!(ret, "VERDICT=DENY\nREASON=NO_PRESENCE").ok();
                    deny_led();
                    ret.push_str("OK\n");
                    return Ok(Some(ret));
                }
                let mut p = load_policy(&self.ks).unwrap_or(Policy { cap: 0, allow: Vec::new() });
                if !p.allow.contains(&a) {
                    if p.allow.len() >= MAX_ALLOW {
                        writeln!(ret, "ERR too many entries (max {})", MAX_ALLOW).ok();
                        return Ok(Some(ret));
                    }
                    p.allow.push(a);
                }
                store_policy(&self.ks, &p).ok();
                writeln!(ret, "ALLOW_N={}", p.allow.len()).ok();
                allow_led();
                ret.push_str("OK\n");
            }
            "denyall" => {
                if !presence(15_000) {
                    writeln!(ret, "VERDICT=DENY\nREASON=NO_PRESENCE").ok();
                    deny_led();
                    ret.push_str("OK\n");
                    return Ok(Some(ret));
                }
                let p = load_policy(&self.ks).unwrap_or(Policy { cap: 0, allow: Vec::new() });
                let p = Policy { cap: p.cap, allow: Vec::new() };
                store_policy(&self.ks, &p).ok();
                writeln!(ret, "ALLOW_N=0").ok();
                allow_led();
                ret.push_str("OK\n");
            }
            "check" | "exec" => {
                let raw = match tokens.next().and_then(|t| unhex::<ACT_LEN>(t, ACT_LEN)) {
                    Some(v) => v,
                    None => {
                        writeln!(ret, "ERR usage: vault {} <{}hex>", sub, ACT_LEN * 2).ok();
                        return Ok(Some(ret));
                    }
                };
                let act = match Action::parse(&raw) {
                    Ok(a) => a,
                    Err(e) => {
                        writeln!(ret, "VERDICT=DENY\nREASON={}", e).ok();
                        return Ok(Some(ret));
                    }
                };
                let o = self.gate(env, &act, sub == "exec", sub == "check");
                Self::fmt_outcome(&mut ret, &o);
                if sub == "exec" {
                    if o.allowed {
                        allow_led();
                    } else {
                        deny_led();
                    }
                }
            }
            "rcpt" => {
                writeln!(ret, "RECEIPTS={}", read_u32(&self.ks, SLOT_COUNT)).ok();
                writeln!(ret, "CHAIN={}", hex(&self.ks.read_app_key(SLOT_CHAIN).unwrap_or([0u8; 32]))).ok();
                writeln!(ret, "LAST={}", hex(&self.ks.read_app_key(SLOT_LAST).unwrap_or([0u8; 32]))).ok();
                ret.push_str("OK\n");
            }
            "serve" => {
                let addr = u8::from_str_radix(tokens.next().unwrap_or("42"), 16).unwrap_or(0x42);
                let n = tokens.next().and_then(|t| t.parse::<u32>().ok()).unwrap_or(1);
                let mut i2c = I2c::new();
                writeln!(ret, "SERVE addr=0x{:02x} rounds={}", addr, n).ok();
                let mut served = 0u32;
                for _ in 0..n {
                    let mut buf = [0u8; ACT_LEN + 2];
                    match i2c.i2c_read(addr, 0x00, &mut buf, false) {
                        Ok(I2cResult::Ack(_)) => {}
                        _ => {
                            writeln!(ret, "SERVE err=no_ack").ok();
                            break;
                        }
                    }
                    if buf[0] & 0x01 == 0 {
                        env.ticktimer.sleep_ms(100).ok();
                        continue;
                    }
                    let act = match Action::parse(&buf[2..]) {
                        Ok(a) => a,
                        Err(e) => {
                            let mut resp = [0u8; 64];
                            resp[0] = 2;
                            let m = e.as_bytes();
                            let l = m.len().min(62);
                            resp[1] = l as u8;
                            resp[2..2 + l].copy_from_slice(&m[..l]);
                            i2c.i2c_write(addr, 0x40, &resp).ok();
                            i2c.i2c_write(addr, 0x00, &[0u8]).ok();
                            served += 1;
                            continue;
                        }
                    };
                    let o = self.gate(env, &act, true, false);
                    let mut resp = [0u8; 64];
                    resp[0] = if o.allowed { 0 } else { 1 };
                    let text = if o.allowed {
                        let mut t = o.render.clone();
                        t.push_str(" OK");
                        t
                    } else {
                        let mut t = o.render.clone();
                        t.push_str(" ");
                        t.push_str(o.reason);
                        t
                    };
                    let tb = text.as_bytes();
                    let l = tb.len().min(60);
                    resp[1] = l as u8;
                    resp[2..2 + l].copy_from_slice(&tb[..l]);
                    if o.allowed {
                        resp[62..64].copy_from_slice(&o.seq.to_le_bytes()[..2]);
                    }
                    i2c.i2c_write(addr, 0x40, &resp).ok();
                    i2c.i2c_write(addr, 0x00, &[0u8]).ok();
                    served += 1;
                    if o.allowed {
                        allow_led();
                    } else {
                        deny_led();
                    }
                }
                writeln!(ret, "SERVED={}", served).ok();
                ret.push_str("OK\n");
            }
            "selftest" => {
                // KAT 1: canonical encoding of the zero action.
                let z = Action {
                    ver: 1,
                    op: 1,
                    value: 0,
                    to: [0u8; 20],
                    nonce: 0,
                    ctx: [0u8; 8],
                };
                let d = z.digest();
                writeln!(ret, "KAT_ZERO={}", hex(&d)).ok();
                writeln!(ret, "KAT_ZERO_OK={}", if hex(&d) == KAT_ZERO { "PASS" } else { "FAIL" }).ok();
                writeln!(ret, "ENC_LEN={}", z.encode().len()).ok();

                // KAT 2: the policy table, evaluated without touching the keystore.
                let pol = Policy {
                    cap: 100_000_000_000_000_000,
                    allow: vec![[0x11u8; 20]],
                };
                let cases: [(u64, [u8; 20], bool); 3] = [
                    (1, [0x11u8; 20], true),
                    (100_000_000_000_000_001, [0x11u8; 20], false),
                    (1, [0x22u8; 20], false),
                ];
                for (i, (v, to, want)) in cases.iter().enumerate() {
                    let got = *v <= pol.cap
                        && (pol.allow.is_empty()
                            || pol.allow.iter().any(|a| a == to));
                    writeln!(
                        ret,
                        "POLICY_{}={}",
                        i,
                        if got == *want { "PASS" } else { "FAIL" }
                    )
                    .ok();
                }
                ret.push_str("OK\n");
            }
            _ => {
                ret.push_str(&self.help());
                ret.push_str("OK\n");
            }
        }

        Ok(Some(ret))
    }
}

// sha256("BAOKEY-ACT-v1\0" || 01 01 0000000000000000 20*00 00000000 8*00)
const KAT_ZERO: &str = "19530212d6dcaa4159ba714d8c91392ac6d218bd52ac6fa1f31e70e73003acde";
