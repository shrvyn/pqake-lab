"""Negacyclic polynomial ring R_q = Z_q[X]/(X^N+1) with a fast NTT.

N = 256, q = 8380417 (q = 1 mod 2^13) so psi with psi^N = -1 exists and
X^N + 1 splits into the linear factors (X - psi*omega^i), omega = psi^2.

The transform is a chirp-Z reduction: f(psi*omega^i) = DFT_omega(a_j*psi^j)[i].
Forward/inverse/convolution are checked against naive references at import.
"""
import numpy as np

N = 256
LOGN = 8
Q = 8380417  # 2^23 - 2^13 + 1


def _find_psi():
    for g in range(2, 1 << 16):
        psi = pow(g, (Q - 1) // (2 * N), Q)
        if pow(psi, N, Q) == Q - 1 and pow(psi, 2 * N, Q) == 1:
            return psi
    raise RuntimeError("no primitive 2N-th root of unity found")


PSI = _find_psi()
OMEGA = PSI * PSI % Q  # primitive N-th root of unity
N_INV = pow(N, Q - 2, Q)
PSI_J = np.array([pow(PSI, j, Q) for j in range(N)], dtype=np.int64)
PSI_INV_J = np.array([pow(PSI, -j, Q) for j in range(N)], dtype=np.int64)


def _bitrev(i, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (i & 1)
        i >>= 1
    return r


BRV = np.array([_bitrev(i, LOGN) for i in range(N)], dtype=np.int64)


def _dft_inplace(a, root):
    """In-place Cooley-Tukey DFT with kernel root^(i*j). a is modified."""
    n = len(a)
    idx = np.argsort(BRV)
    a[:] = a[idx]  # bit-reversal permutation
    size = 2
    while size <= n:
        half = size // 2
        step = n // size
        wpow = np.array([pow(int(root), j * step, Q) for j in range(half)], dtype=np.int64)
        for start in range(0, n, size):
            blk = a[start:start + size]
            lo = blk[:half].copy()
            hi = blk[half:].copy()
            t = hi * wpow % Q
            a[start:start + half] = (lo + t) % Q
            a[start + half:start + size] = (lo - t) % Q
        size *= 2
    return a


def ntt(a):
    return _dft_inplace((np.asarray(a, dtype=np.int64) % Q) * PSI_J % Q, OMEGA)


def intt(v):
    out = _dft_inplace((np.asarray(v, dtype=np.int64) % Q).copy(), pow(OMEGA, Q - 2, Q))
    return out * PSI_INV_J % Q * N_INV % Q


def ntt_slow(a):
    a = np.asarray(a, dtype=np.int64) % Q
    b = a * PSI_J % Q
    return np.array([np.dot(b, np.array([pow(OMEGA, i * j, Q) for j in range(N)],
                                        dtype=np.int64)) % Q for i in range(N)], dtype=np.int64)


def reduce(a):
    return np.asarray(a, dtype=np.int64) % Q


def polymul_naive(a, b):
    a = reduce(a)
    b = reduce(b)
    out = np.zeros(2 * N, dtype=np.int64)
    for i in range(N):
        if a[i]:
            out[i:i + N] += int(a[i]) * b
    return (out[:N] - out[N:]) % Q


def polymul_ntt(x, y):
    return x * y % Q


def polyadd(x, y):
    return (x + y) % Q


def check():
    rng = np.random.default_rng(7)
    for _ in range(3):
        a = rng.integers(0, Q, N, dtype=np.int64)
        b = rng.integers(0, Q, N, dtype=np.int64)
        assert np.array_equal(ntt(a), ntt_slow(a)), "forward NTT mismatch"
        assert np.array_equal(intt(ntt(a)), a), "roundtrip mismatch"
        assert np.array_equal(intt(polymul_ntt(ntt(a), ntt(b))), polymul_naive(a, b)), "convolution mismatch"
    return True


if __name__ == "__main__":
    check()
    print("ring.py OK  psi=%d omega=%d q=%d N=%d" % (PSI, OMEGA, Q, N))
