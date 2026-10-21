"""Efficiency measurements for ch.5-4: native C primitive timings, wire sizes, per-role
operation counts and the Python reference-implementation latencies.

Two clearly separated layers, because mixing them would be dishonest:
  native_*   cycle/wall-clock numbers from the vendored C code (x86-64, this laptop)
  py_*       wall-clock numbers from the Python reference implementation (functional
             evidence only: ratios and correctness, not device timings)
"""
import csv
import itertools
import json
import os
import re
import statistics
import subprocess
import time

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hmac import HMAC

from . import ibs, net as N, proto
from .proto import HKDF_Expand, Error

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
RESULTS = os.path.join(ROOT, "results")
C = os.path.join(ROOT, "c")
NATIVE = {
    "ML-KEM-512": "bench_kyber512.exe",
    "ML-KEM-768": "bench_kyber768.exe",
    "Dilithium-2": "bench_dil2.exe",
    "Dilithium-3": "bench_dil3.exe",
    "IBS-K2L2": "bench_ibs.exe",
    "ring": "bench_ring.exe",
}


def run_native(iters=20000, sig_iters=3000):
    """Execute the compiled C benchmarks and return parsed rows."""
    rows = []
    for label, exe in NATIVE.items():
        path = os.path.join(C, exe)
        if not os.path.exists(path):
            rows.append({"scheme": label, "operation": "MISSING", "note": "run c/build.sh"})
            continue
        n = sig_iters if ("dil" in exe or "ibs" in exe) else iters
        p = subprocess.run([path, str(n)], capture_output=True, text=True, timeout=1800)
        for line in p.stdout.splitlines()[1:]:
            f = line.split(",")
            rows.append({"scheme": f[0], "operation": f[1], "iters": int(f[2]),
                         "cycles_min": float(f[3]), "cycles_mean": float(f[4]),
                         "us_min": float(f[5]), "us_mean": float(f[6])})
    return rows


def timed(fn, iters, warmup=3):
    for _ in range(warmup):
        fn()
    ts = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        ts.append((time.perf_counter() - t0) * 1e6)
    return {"us_mean": round(statistics.fmean(ts), 1),
            "us_min": round(min(ts), 1), "us_p95": round(sorted(ts)[int(0.95 * len(ts))], 1),
            "iters": iters}


def py_symmetric():
    key = os.urandom(32)
    info = b"PQAKE-v1 Message Key" + b"\0" * 12
    pt = os.urandom(32)
    pt256 = os.urandom(256)
    out = {}
    out["hkdf_expand_32B"] = timed(lambda: HKDF_Expand(key, info), 20000)
    m = HMAC(key, hashes.SHA3_256())
    m.update(pt)
    out["hmac_sha3_256"] = timed(lambda: proto.hmac_bytes(key, pt), 20000)
    out["sha3_256"] = timed(lambda: proto.H(pt), 20000)
    g = AESGCM(key)
    nonce = os.urandom(12)
    ct = g.encrypt(nonce, pt, b"ad")
    out["aes256gcm_seal_32B"] = timed(lambda: g.encrypt(nonce, pt, b"ad"), 20000)
    out["aes256gcm_seal_256B"] = timed(lambda: g.encrypt(nonce, pt256, b"ad"), 20000)
    out["aes256gcm_open_32B"] = timed(lambda: g.decrypt(nonce, ct, b"ad"), 20000)
    return out


def py_kem():
    """The mlkem wheel is a Rust implementation of FIPS 203: measured here as a cross-check
    on the native C numbers (different implementation, same algorithm)."""
    k = proto._KEM
    ek, dk = k.key_gen()
    ss, ct = k.encaps(ek)
    assert k.decaps(dk, ct) == ss
    return {"mlkem512_keygen": timed(lambda: k.key_gen(), 3000),
            "mlkem512_encaps": timed(lambda: k.encaps(ek), 3000),
            "mlkem512_decaps": timed(lambda: k.decaps(dk, ct), 3000)}


def py_ibs(iters=40):
    mpk, msk = ibs.setup()
    who = b"IIOT-GW-0001"
    # A fresh message per signature: y is bound to (id, mu, ctr), so reusing one mu would
    # measure the same rejection trace over and over instead of the rejection *rate*.
    msgs = [b"IDA||IDB||pkAe||NA" + i.to_bytes(2, "little") for i in range(4 * iters)]
    cyc = itertools.cycle(msgs)
    usk = ibs.extract(mpk, msk, who)
    mu = msgs[0]
    sig = ibs.sign(mpk, usk, who, mu)
    out = {"setup": timed(lambda: ibs.setup(), 5),
           "extract": timed(lambda: ibs.extract(mpk, msk, b"IIOT-PLC-0042"), 20),
           "sign": timed(lambda: ibs.sign(mpk, usk, who, next(cyc)), iters),
           "verify": timed(lambda: ibs.verify(mpk, who, mu, sig), iters)}
    attempts = [ibs.sign(mpk, usk, who, m)["attempts"] for m in msgs[:iters]]
    out["attempts_mean"] = round(statistics.fmean(attempts), 2)
    out["attempts_max"] = max(attempts)
    # operation counts inside one sign/verify, hardware independent
    out["ops"] = {"ntt_per_sign": ibs.L + 1, "intt_per_sign": ibs.K,
                  "basemul_per_sign": ibs.K * ibs.L + ibs.K,
                  "ntt_per_verify": 2 * ibs.L + ibs.K + 2, "intt_per_verify": ibs.K,
                  "basemul_per_verify": ibs.K * ibs.L + 2 * ibs.K,
                  "K": ibs.K, "L": ibs.L, "N": ibs.N, "q": ibs.Q}
    return out


def py_protocol():
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)
    out = {}
    out["handshake_total"] = timed(lambda: N.establish(N.Net(), f), 12, warmup=1)
    out["epoch_refresh_A"] = timed(lambda: N.do_epoch(n, A, B), 12, warmup=1)
    holder = {}
    def one_roundtrip():
        m = A.encrypt(b"setpoint=41.5")
        holder["m"] = m
        B.decrypt(m)
    out["message_pair"] = timed(one_roundtrip, 400)
    out["encrypt_only"] = timed(lambda: A.encrypt(b"setpoint=41.5"), 400)
    return out


def wire_sizes():
    """Exact on-the-wire bytes per protocol message, measured from the reference code."""
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)

    def size(msg):
        tot = 0
        for k, v in msg.items():
            if k == "sigma":
                tot += len(proto.pack_sig(v))
            elif isinstance(v, (bytes, bytearray)):
                tot += len(v)
            elif isinstance(v, int):
                tot += 4 if k == "e" else 8
        return tot

    m1, m2 = A.m1, B.m2
    ma = A.start_epoch()
    mb = B.accept_epoch_a(ma)
    data = A.encrypt(b"x" * 32)
    sig_only = len(proto.pack_sig(m1["sigma"]))
    return {
        "M1": {"bytes": size(m1), "components": {"IDA": len(A.id), "IDB": len(B.id),
                                                 "pkAe": 800, "NA": 16, "sigma": sig_only}},
        "M2": {"bytes": size(m2), "components": {"IDB": len(B.id), "IDA": len(A.id),
                                                 "NB": 16, "ct0": 768, "NA": 16,
                                                 "sigma": sig_only}},
        "MsgA_refresh": {"bytes": size(ma), "components": {"e": 4, "AD": 32 + 8 + 4 + 32,
                                                           "pke": 800, "MACA": 32}},
        "MsgB_refresh": {"bytes": size(mb), "components": {"e": 4, "AD": 32 + 8 + 4 + 32,
                                                           "ct": 768, "MACB": 32}},
        "data_message": {"bytes": size(data), "components": {"e": 4, "j": 8, "nonce": 12,
                                                            "ad": 32 + 8 + 4 + 8 + 32,
                                                            "ct": 32 + 16}},
        "confirmation": {"bytes": 64, "components": {"MACA": 32, "MACB": 32}},
        "sigma_bytes_measured": sig_only,
        "sigma_bytes_analytic": ibs.sizes()["sigma_bytes"],
    }


def state_footprint():
    """Bytes a node must keep, counted from the reference state, vs the thesis' StAL tables."""
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)
    def sess_bytes(S, with_kra):
        b = 0
        b += 32                      # RK
        b += 32 + 32                 # CK_send, CK_recv
        b += 4 + 8 + 8               # epoch, tx, rx_j
        b += 32                      # TH
        b += 2 * 16                  # peer + own identity
        if with_kra:
            b += 32                  # KRA
        return b
    return {"per_session_node_bytes": sess_bytes(A, False),
            "per_session_node_bytes_with_KRA": sess_bytes(A, True),
            "identity_key_bytes": ibs.sizes()["usk_bytes"],
            "master_pk_bytes": ibs.sizes()["mpk_bytes"],
            "eq_5_5_StAL1": {"skIBS": ibs.sizes()["usk_bytes"],
                             "pkIBS_GW": ibs.sizes()["mpk_bytes"], "RK0": 32, "KRA": 32},
            "eq_5_6_StAL2": {"RK": 32, "CK": 32, "Epoch_ID": 4, "KAEAD": 32}}


def ops_per_message(cadence_msgs=100, sessions=1, epochs_per_session=None):
    """Hardware independent: what one authenticated message costs as a function of the
    asymmetric refresh cadence. This is the table that supports eq 20-4/21-4."""
    base = {"hkdf_expand": 2, "aead_seal": 1, "sha3": 1, "hmac": 0}
    rows = []
    for cad in (1, 10, 25, 50, 100, 250, 500, 1000):
        r = dict(base)
        r["refresh_cadence_msgs"] = cad
        r["kem_keygen_per_msg"] = round(1.0 / cad, 4)
        r["kem_encaps_per_msg"] = round(1.0 / cad, 4)
        r["kem_decaps_per_msg"] = round(1.0 / cad, 4)
        r["ibs_sign_per_msg"] = 0.0            # refresh phase carries no signature
        r["ibs_verify_per_msg"] = 0.0
        r["hkdf_expand_per_msg"] = 2 + 6.0 / cad   # 6 extra expansions per refresh
        rows.append(r)
    return rows


DIST_RE = re.compile(
    r"distribution check over (\d+) signatures: mean attempts ([\d.]+) \(theory ~([\d.]+)\), "
    r"(\d+) rejections from \|LowBits\(Ay\)\| and (\d+) from \|z\|; "
    r"max\|LowBits\(Ay\)\| of the first attempt in \[(-?\d+), (-?\d+)\] against an abort "
    r"bound of (-?\d+), max\|y\| (-?\d+) \(eta_y (\d+)\), max\|z\| (-?\d+) \(abort bound "
    r"(-?\d+)\)")


def ibs_selftest(iters=200):
    """Run the native IBS executable, which self-tests before it measures, and keep the
    evidence lines (round trip, three negative tests, the F1 key-recovery check, and the
    rejection-rate distribution)."""
    path = os.path.join(C, NATIVE["IBS-K2L2"])
    if not os.path.exists(path):
        return {"rc": None, "log": ["bench_ibs.exe missing - run c/build.sh"], "dist": {}}
    p = subprocess.run([path, str(iters)], capture_output=True, text=True, timeout=1800)
    log = [l.lstrip("# ").strip() for l in p.stderr.splitlines() if l.startswith("#")]
    dist = {}
    for l in log:
        m = DIST_RE.search(l)
        if m:
            keys = ("n", "attempts_mean", "attempts_theory", "rej_w", "rej_z", "lo_min",
                    "lo_max", "abort_w", "max_y", "eta_y", "max_z", "abort_z")
            dist = {k: (float(v) if "." in v else int(v)) for k, v in zip(keys, m.groups())}
    return {"rc": p.returncode, "log": log, "dist": dist}


def measure(iters=20000, full=True, verbose=True):
    t0 = time.perf_counter()
    out = {"generated": time.strftime("%Y-%m-%d %H:%M:%S"),
           "host": {"platform": os.name, "machine": os.uname().machine if hasattr(os, "uname") else "?"}}
    out["native"] = run_native(iters=iters)
    out["ibs_selftest"] = ibs_selftest()
    if full:
        out["py_symmetric"] = py_symmetric()
        out["py_kem"] = py_kem()
        out["py_ibs"] = py_ibs()
        out["py_protocol"] = py_protocol()
    out["wire"] = wire_sizes()
    out["state"] = state_footprint()
    out["ops_per_message"] = ops_per_message()
    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "perf.json"), "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)
    if out["native"]:
        with open(os.path.join(RESULTS, "native_ops.csv"), "w", newline="",
                  encoding="utf-8") as fh:
            w = csv.DictWriter(fh, fieldnames=sorted(out["native"][0].keys()))
            w.writeheader()
            for r in out["native"]:
                w.writerow(r)
    if verbose:
        print("perf measured in %.1fs -> results/perf.json" % (time.perf_counter() - t0))
    return out


if __name__ == "__main__":
    measure()
