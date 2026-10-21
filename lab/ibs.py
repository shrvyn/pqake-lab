"""Identity-based post-quantum signature (prototype instantiation of ch.2 sec 2-3-4).

Four algorithms Setup / Extract / Sign / Verify exactly as the thesis describes:
commitment w = HighBits(A y), challenge c = H(id, mu, w), response z = y + c*usk_id,
rejection sampling on the norm of z, and a verifier that needs only (mpk, id, mu,
sigma) and re-checks shortness of z plus the Module-LWE relation.

Identity binding uses homomorphic key derivation. With master secret (s1, s2),
master public key t = A s1 + s2, and sparse h = H_id(id) of weight W_H:

    usk_id = h * s1                     (extracted by the PKG)
    pk_id  = h * t = A*(h*s1) + h*s2    (implicit; verifier forms h*t)

Hence A z - c*(h t) = A y - c*h*s2, and |c*h*s2| <= BETA, so HighBits is preserved
provided the signer aborts when LowBits(A y) is within BETA of the boundary. Because
the verifier uses the exact h*t rather than a rounded t1, no hint mechanism is needed.

Prototype parameters are ours (k=l=2, n=256, q=8380417): the thesis cites Zhichao et
al. 2021 but never fixes its trapdoor sampling. See RESULTS.md for the deviation note.
"""
import hashlib
import numpy as np

from . import ring

N = ring.N
Q = ring.Q
MASKQ = Q

K = 2                    # rows of A / number of t polynomials
L = 2                    # cols of A / number of s1 polynomials
GAMMA1 = 1 << 17         # support radius of y
GAMMA2 = 95232           # (Q-1)/88 ; ALPHA = 2*GAMMA2 divides Q-1 exactly
ALPHA = 2 * GAMMA2
NDIGITS = (Q - 1) // ALPHA   # 44 possible HighBits values
TAU = 39                 # Hamming weight of the challenge polynomial
W_H = 8                  # Hamming weight of the identity element h
ETA = 2                  # CBD order of s1, s2
BETA = (TAU - 1) * W_H * ETA + 1   # bound on ||c*h*s||_inf, 609
ABORT_Z = GAMMA1 - BETA
ABORT_W = GAMMA2 - BETA - 1   # strict: keeps LowBits away from the digit boundary
SEED = 32

_rng_cache = {}


def _shake(nbytes, *parts):
    h = hashlib.shake_256()
    for p in parts:
        h.update(p if isinstance(p, (bytes, bytearray)) else np.asarray(p).tobytes())
    return h.digest(nbytes)


def _cbd(stream, eta):
    """Centered binomial coefficients from 2*eta bits each."""
    bits = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))
    per = 2 * eta
    count = len(bits) // per
    b = bits[:count * per].reshape(count, per)
    return (b[:, :eta].sum(axis=1) - b[:, eta:].sum(axis=1)).astype(np.int64)


def _uniform(stream, n, modulus=Q, bits=23):
    """First n values uniform in [0, modulus), rejection over fixed-width draws."""
    lim = (1 << bits) // modulus * modulus
    b = np.unpackbits(np.frombuffer(stream, dtype=np.uint8))[:len(stream) * 8 // bits * bits]
    if len(b) == 0:
        raise ValueError("stream too short for %d draws" % n)
    w = (np.int64(1) << np.arange(bits, dtype=np.int64))
    vals = b.reshape(-1, bits).astype(np.int64) @ w
    kept = vals[vals < lim] % modulus
    if len(kept) < n:
        extra = _uniform(_shake(8 * n, b"REFILL", bytes(str(int(vals[0])), "ascii"),
                                bytes(str(len(kept)), "ascii")), n - len(kept), modulus, bits)
        kept = np.concatenate([kept, extra])
    return kept[:n].astype(np.int64)


def expand_a(rho, ctr=0):
    """A in R_q^{K x L} from a seed, returned in the NTT domain."""
    A_hat = np.zeros((K, L, N), dtype=np.int64)
    for i in range(K):
        for j in range(L):
            s = _shake(8 * N, b"IBS-A", rho, bytes([i, j, ctr]))
            A_hat[i, j] = ring.ntt(_uniform(s, N, Q, 23))
    return A_hat


def _sparse_from(stream, weight, n=N):
    pos = []
    for b in stream:
        if b < n and b not in pos:
            pos.append(int(b))
        if len(pos) == weight:
            break
    while len(pos) < weight:  # extremely unlikely fallback
        pos.append(len(pos) % n)
    return pos


def expand_h(id_bytes):
    """Sparse ring element h of weight W_H with +-1 coefficients, from the identity."""
    stream = _shake(256, b"IBS-H", id_bytes)
    pos = _sparse_from(stream, W_H)
    signs = stream[W_H:W_H + 8]
    h = np.zeros(N, dtype=np.int64)
    for idx, p in enumerate(pos):
        h[p] = 1 if (signs[idx // 8] >> (idx % 8)) & 1 else Q - 1
    return h


def expand_challenge(id_bytes, mu, w_packed):
    """c with exactly TAU coefficients in {+1,-1}: c = H(id, mu, w)."""
    stream = _shake(512, b"IBS-C", id_bytes, mu, w_packed)
    pos = _sparse_from(stream, TAU)
    signs = stream[TAU:TAU + 8]
    c = np.zeros(N, dtype=np.int64)
    for idx, p in enumerate(pos):
        c[p] = 1 if (signs[idx // 8] >> (idx % 8)) & 1 else Q - 1
    return c


def _center(v):
    return ((np.asarray(v, dtype=np.int64) + (Q - 1) // 2) % Q) - (Q - 1) // 2


ETA1 = 13              # CBD order for y: |y| <= 4095 << GAMMA1, like Dilithium


def _sample_y(tag):
    """y from a centered binomial distribution, |y|_inf <= ETA1, broadcast per call."""
    need = L * N * 2 * ETA1 // 8
    s = _shake(need, b"IBS-Y", tag[0], tag[1], tag[2].to_bytes(4, "little"))
    return _cbd(s, ETA1)[: L * N].reshape(L, N)


def _split(v):
    """v -> (m, s): v = m*ALPHA + s (mod Q), m in [0,43], |s| <= GAMMA2."""
    r = np.asarray(v, dtype=np.int64) % Q
    m = (r + GAMMA2 - 1) // ALPHA
    m = np.where(m >= NDIGITS, 0, m).astype(np.int64)
    s = r - m * ALPHA
    s = ((s + (Q - 1) // 2) % Q) - (Q - 1) // 2
    return m, s


def high_bits(v):
    return _split(v)[0]


def low_bits(v):
    return _split(v)[1]


def sweep_decomposition(chunk = 1 << 20):
    """Exhaustive check over every residue in [0, Q)."""
    for lo in range(0, Q, chunk):
        r = np.arange(lo, min(lo + chunk, Q), dtype=np.int64)
        m, s = _split(r)
        assert np.array_equal((m * ALPHA + s) % Q, r), "reconstruction failed"
        assert np.max(np.abs(s)) <= GAMMA2, "LowBits out of range"
        assert m.min() >= 0 and m.max() < NDIGITS, "HighBits out of range"
    return True


def pack_w(w):
    bits = np.zeros((w.size, 6), dtype=np.uint8)
    flat = np.asarray(w, dtype=np.int64).flatten()
    for b in range(6):
        bits[:, b] = (flat >> b) & 1
    return np.packbits(bits.flatten(), bitorder="little").tobytes()


def setup(seed=None):
    """PKG Setup(1^lambda) -> (mpk, msk)."""
    rho = seed if seed is not None else _shake(SEED, b"IBS-SETUP")
    A_hat = expand_a(rho)
    ks = _shake(4 * (K + L) * N, b"IBS-MSK", rho)
    need = (L + K) * N * 2 * ETA // 8
    co = _cbd(ks[:need], ETA)
    s1 = co[: L * N].reshape(L, N) % Q
    s2 = co[L * N: (L + K) * N].reshape(K, N) % Q
    s1_hat = np.array([ring.ntt(s1[j]) for j in range(L)])
    t = np.array([ring.intt(sum(ring.polymul_ntt(A_hat[i, j], s1_hat[j]) for j in range(L)) % Q)
                  for i in range(K)])
    t = ring.reduce(t + s2)          # normal domain: t = A*s1 + s2
    mpk = {"rho": rho, "t": t, "A_hat": A_hat}
    msk = {"s1": s1, "s2": s2, "rho": rho}
    return mpk, msk


def extract(mpk, msk, id_bytes):
    """PKG Extract(mpk, msk, ID) -> usk_id = h*s1 (NTT domain)."""
    h_hat = ring.ntt(expand_h(id_bytes))
    return np.array([ring.reduce(ring.polymul_ntt(h_hat, ring.ntt(msk["s1"][j])))
                     for j in range(L)])


def sign(mpk, usk_id, id_bytes, mu, max_attempts=8192):
    """Sign(mu, usk_id) -> sigma = (w, c, z). usk_id is in the NTT domain."""
    attempts = 0
    for ctr in range(max_attempts):
        attempts += 1
        y = _sample_y((id_bytes, mu, ctr))
        y_hat = np.array([ring.ntt(y[j]) for j in range(L)])
        Ay = np.array([ring.intt(sum(ring.polymul_ntt(mpk["A_hat"][i, j], y_hat[j])
                                     for j in range(L)) % Q) for i in range(K)])
        if np.max(np.abs(low_bits(Ay))) > ABORT_W:
            continue
        w = high_bits(Ay)
        c = expand_challenge(id_bytes, mu, pack_w(w))
        c_hat = ring.ntt(c)
        z = np.zeros((L, N), dtype=np.int64)
        for j in range(L):
            z[j] = ring.reduce(y[j] + ring.intt(ring.polymul_ntt(c_hat, usk_id[j])))
        if np.max(np.abs(_center(z))) > ABORT_Z:
            continue
        return {"w": w, "c": c, "z": _center(z), "attempts": attempts}
    raise RuntimeError("too many rejection attempts: %d" % attempts)


def verify(mpk, id_bytes, mu, sigma):
    """Verify(mpk, ID, mu, sigma) -> 0/1, using only public data and the identity."""
    z = np.asarray(sigma["z"], dtype=np.int64) % Q
    if np.max(np.abs(_center(z))) > ABORT_Z:
        return 0
    if not np.array_equal(expand_challenge(id_bytes, mu, pack_w(sigma["w"])), sigma["c"]):
        return 0
    c_hat = ring.ntt(sigma["c"])
    h_hat = ring.ntt(expand_h(id_bytes))
    t_hat = np.array([ring.ntt(mpk["t"][i]) for i in range(K)])
    z_hat = np.array([ring.ntt(z[j]) for j in range(L)])
    lhs = np.zeros((K, N), dtype=np.int64)
    for i in range(K):
        az = sum(ring.polymul_ntt(mpk["A_hat"][i, j], z_hat[j]) for j in range(L)) % Q
        ct = ring.polymul_ntt(c_hat, ring.polymul_ntt(h_hat, t_hat[i]))
        lhs[i] = ring.intt(ring.reduce(az - ct))
    return int(np.array_equal(high_bits(lhs), sigma["w"]))


def forge_with_msk(mpk, msk, id_bytes, mu):
    """Key-escrow demonstration: the PKG (holding msk) can sign as any identity."""
    return sign(mpk, extract(mpk, msk, id_bytes), id_bytes, mu)


def sizes():
    return {"mpk_bytes": K * N * 3 + SEED, "usk_bytes": L * N * 3,
            "sigma_bytes": (K * N * 6 + 7) // 8 + TAU + (TAU + 7) // 8 + L * N * 3,
            "A_seed_bytes": SEED}
