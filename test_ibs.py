"""Self-tests for the identity-based signature: completeness, soundness, escrow."""
import time

import numpy as np

from lab import ibs, ring


def main():
    print("== ring check")
    ring.check()
    print("   negacyclic NTT == naive convolution, roundtrip OK")

    print("== decomposition: exhaustive sweep over all residues mod q")
    ibs.sweep_decomposition()
    print("   v = HighBits(v)*ALPHA + LowBits(v) for all %d residues, |LowBits| <= %d, digits < %d"
          % (ibs.Q, ibs.GAMMA2, ibs.NDIGITS))

    rng = np.random.default_rng(3)
    bad = 0
    trials = 0
    for _ in range(3000):
        v = rng.integers(0, ibs.Q, 256)
        d = rng.integers(-ibs.BETA, ibs.BETA + 1, 256)
        if np.max(np.abs(ibs.low_bits(v))) <= ibs.ABORT_W:
            trials += 1
            if not np.array_equal(ibs.high_bits(v), ibs.high_bits((v + d) % ibs.Q)):
                bad += 1
    assert bad == 0, "abort bound does not guarantee digit stability"
    print("   digit stability: |LowBits|<=ABORT_W and |d|<=BETA(%d) => HighBits unchanged (%d trials, 0 failures)"
          % (ibs.BETA, trials))

    print("== setup")
    t0 = time.perf_counter()
    mpk, msk = ibs.setup()
    t_setup = time.perf_counter() - t0
    print("   %.1f ms  mpk=%d bytes (t=%d coeffs x %d bits)" % (t_setup * 1e3, ibs.sizes()["mpk_bytes"], ibs.K, 23))

    idA = b"IIOT-GW-0001"
    idB = b"IIOT-NODE-0042"
    t0 = time.perf_counter()
    uskA = ibs.extract(mpk, msk, idA)
    t_extract = time.perf_counter() - t0
    print("== extract  %.1f ms  usk=%d bytes" % (t_extract * 1e3, ibs.sizes()["usk_bytes"]))

    mu = b"PQAKE-v1 handshake transcript 0"
    t0 = time.perf_counter()
    sig = ibs.sign(mpk, uskA, idA, mu)
    t_sign = time.perf_counter() - t0
    t0 = time.perf_counter()
    ok = ibs.verify(mpk, idA, mu, sig)
    t_verify = time.perf_counter() - t0
    print("== sign     %.1f ms (attempts=%d)  sigma=%d bytes" % (t_sign * 1e3, sig["attempts"], ibs.sizes()["sigma_bytes"]))
    print("== verify    %.1f ms -> %d" % (t_verify * 1e3, ok))
    assert ok == 1, "honest signature must verify"

    print("== soundness probes (all must be 0)")
    probes = {
        "wrong message": ibs.verify(mpk, idA, mu + b"x", sig),
        "wrong identity": ibs.verify(mpk, idB, mu, sig),
        "tampered z": ibs.verify(mpk, idA, mu, {**sig, "z": (sig["z"] + 1) % ring.Q}),
        "tampered w": ibs.verify(mpk, idA, mu, {**sig, "w": (sig["w"] + 1) % ibs.NDIGITS}),
        "fresh w with stale c": ibs.verify(mpk, idA, mu, {**sig, "w": np.zeros_like(sig["w"])}),
        "oversized z": ibs.verify(mpk, idA, mu, {**sig, "z": sig["z"] + ibs.ABORT_Z + 1}),
    }
    for name, res in probes.items():
        print("   %-22s -> %d" % (name, res))
    assert all(v == 0 for v in probes.values()), "a forgery was accepted"

    print("== key escrow (PKG can sign for any identity)")
    forged = ibs.forge_with_msk(mpk, msk, idB, mu)
    print("   PKG-signed message as %s verifies: %d" % (idB.decode(), ibs.verify(mpk, idB, mu, forged)))

    t0 = time.perf_counter()
    for _ in range(12):
        ibs.sign(mpk, uskA, idA, mu + str(time.perf_counter()).encode())
    avg_sign = (time.perf_counter() - t0) / 12
    t0 = time.perf_counter()
    for _ in range(12):
        ibs.verify(mpk, idA, mu, sig)
    avg_verify = (time.perf_counter() - t0) / 12
    print("== mean over 12 runs: sign %.1f ms, verify %.1f ms" % (avg_sign * 1e3, avg_verify * 1e3))
    return {"setup_ms": t_setup * 1e3, "extract_ms": t_extract * 1e3,
            "sign_ms": t_sign * 1e3, "verify_ms": t_verify * 1e3,
            "mean_sign_ms": avg_sign * 1e3, "mean_verify_ms": avg_verify * 1e3,
            "attempts": sig["attempts"], "sizes": ibs.sizes()}


if __name__ == "__main__":
    main()


def master_key_recovery_attack():
    """Can a node holding only its own usk_id recover the PKG master secret s1?

    Variant A (thesis as described) sets usk_id = h*s1 with h = H_id(id) public.
    If h is invertible in R_q then s1 = usk_id * h^-1: every node holds the master key.
    """
    mpk, msk = ibs.setup()
    idA = b"IIOT-GW-0001"
    usk = ibs.extract(mpk, msk, idA)
    h_hat = ring.ntt(ibs.expand_h(idA))
    nz = int(np.count_nonzero(h_hat))
    print("== master-key recovery attack on the as-described construction")
    print("   h=H_id(ID) has %d/256 invertible NTT components" % nz)
    if nz < ring.N:
        print("   h is a zero divisor: full recovery not possible for this identity")
        return False
    inv = np.array([pow(int(v), ring.Q - 2, ring.Q) for v in h_hat], dtype=np.int64)
    s1_guess = np.array([usk[j] * inv % ring.Q for j in range(ibs.L)])
    s1_true = np.array([ring.ntt(msk["s1"][j]) for j in range(ibs.L)])
    leaked = bool(np.array_equal(s1_guess, s1_true))
    print("   recovered NTT-domain s1 == master secret: %s" % leaked)
    if leaked:
        forged_id = b"IIOT-NODE-9999"
        forged_key = ibs.extract(mpk, {"s1": [ring.intt(s1_guess[j]) for j in range(ibs.L)],
                                       "s2": msk["s2"], "rho": msk["rho"]}, forged_id)
        mu = b"critical setpoint command"
        sig = ibs.sign(mpk, forged_key, forged_id, mu)
        print("   node then forged a valid signature as %s: verify=%d"
              % (forged_id.decode(), ibs.verify(mpk, forged_id, mu, sig)))
    return leaked
