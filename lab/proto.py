"""Reference implementation of P.Q.A.K.E. v1 (thesis ch.4), equation by equation.

Phase 1  initial AKA      : eq 4-4..4-10, key schedule eq 4-11..4-19, confirmation eq 4-20
Phase 2  asymmetric ratchet per epoch e : eq 4-23..4-33
Phase 3  symmetric message ratchet      : eq 4-34..4-37

Backends: ML-KEM-512 (FIPS 203) via `mlkem`, the identity-based signature in lab.ibs,
AES-256-GCM as the AEAD, HKDF/HMAC over SHA3-256 as specified.

Exposure is modelled explicitly because every forward-secrecy / post-compromise claim
depends on *which* state the adversary obtains:
    "message_state" : RK, CK_send, CK_recv, epoch, counters, TH   (ACCE StateReveal)
    "session_state" : message_state + Ksess
    "kra"           : + KRA and sk_id (deliberately OUTSIDE the thesis threat model)
    "ephemeral"     : + the handshake / refresh KEM secrets (eCK ephemeral reveal)
"""
import hashlib
import hmac as _hmacmod
import os

import numpy as np
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as _hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from mlkem import ML_KEM, ParameterSet, EncapsKey, DecapsKey

from . import ibs

LAM = 32                      # lambda = 256-bit keys
NAN = 16                      # 128-bit nonces (eq 4-4)
_KEM = ML_KEM(ParameterSet.ML_KEM_512)

LAB_KRA = b"PQAKE-v1 Long-Term-Key"     # eq 4-14
LAB_RK = b"PQAKE-v1 Root Key"           # eq 4-15, 4-31
LAB_SK = b"PQAKE-v1 Session Key"        # eq 4-16
LAB_KC = b"PQAKE-v1 Confirmation Key"   # eq 4-17
LAB_CKA = b"PQAKE-v1 Chain Key A"       # eq 4-18
LAB_CKB = b"PQAKE-v1 Chain Key B"       # eq 4-19
LAB_SEND = b"PQAKE-v1 Send Chain"       # eq 4-32
LAB_RECV = b"PQAKE-v1 Receive Chain"    # eq 4-33
LAB_MK = b"PQAKE-v1 Message Key"        # eq 4-34
LAB_NCK = b"PQAKE-v1 Next Chain Key"    # eq 4-35


class Error(Exception):
    """Protocol abort."""


# ------------------------------------------------------------------ primitives
def H(*parts):
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p if isinstance(p, (bytes, bytearray)) else bytes(p))
    return h.digest()


def hmac_bytes(key, data):
    m = _hmac.HMAC(key, hashes.SHA3_256())
    m.update(data)
    return m.finalize()


def HKDF_Expand(prk, info, length=LAM):
    """RFC 5869 HKDF-Expand over SHA3-256 (eq 4-14..4-19, 4-32..4-35)."""
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac_bytes(prk, t + info + bytes([i]))
        okm += t
        i += 1
    return okm[:length]


def HKDF_Extract(salt, ikm):
    """RFC 5869 HKDF-Extract over SHA3-256 (eq 4-13, 4-31)."""
    return hmac_bytes(salt, ikm)


def kem_keygen():
    ek, dk = _KEM.key_gen()
    return ek, dk


def kem_encaps(ek_bytes):
    ss, ct = _KEM.encaps(EncapsKey.from_bytes(ek_bytes))
    return bytes(ct), ss


def kem_decaps(dk, ct_bytes):
    return _KEM.decaps(dk, ct_bytes)


def consteq(a, b):
    return _hmacmod.compare_digest(bytes(a), bytes(b))


# ------------------------------------------------- signature encoding
def pack_sig(sig):
    """Deterministic byte encoding of sigma = (w, c, z); used in transcripts and sizes."""
    w = np.asarray(sig["w"], dtype=np.uint8).flatten()
    bits = np.zeros((w.size, 6), dtype=np.uint8)
    src = np.asarray(sig["w"], dtype=np.int64).flatten()
    for b in range(6):
        bits[:, b] = ((src >> b) & 1).astype(np.uint8)
    wp = np.packbits(bits.flatten(), bitorder="little").tobytes()
    cpos = np.nonzero(np.asarray(sig["c"], dtype=np.int64).flatten())[0]
    csign = (np.asarray(sig["c"], dtype=np.int64).flatten()[cpos] == 1).astype(np.uint8)
    cp = cpos.astype(np.uint8).tobytes() + np.packbits(csign, bitorder="little").tobytes()
    # z coefficients are reduced mod q (q < 2^23), so 3 bytes each, little endian
    zv = (np.asarray(sig["z"], dtype=np.int64) % ibs.Q).astype(np.uint32).flatten()
    zb = np.zeros(zv.size * 3, dtype=np.uint8)
    i = np.arange(zv.size)
    zb[3 * i] = (zv & 0xFF).astype(np.uint8)
    zb[3 * i + 1] = ((zv >> 8) & 0xFF).astype(np.uint8)
    zb[3 * i + 2] = ((zv >> 16) & 0xFF).astype(np.uint8)
    return wp + cp + zb.tobytes()


# ------------------------------------------------------------------- session
class Session:
    def __init__(self, identity, sk_id, role, mpk, replay_cache=None):
        self.id = identity
        self.sk_id = sk_id                  # long-term identity key, not "session state"
        self.mpk = mpk
        self.role = role                    # "initiator" | "responder"
        self.state = {}                     # what a message_state exposure reveals
        self.kra = None                     # refresh-authentication key
        # F2 fix: NA freshness lives with the node, not with one session instance, so a
        # replayed M1 is refused even when it reaches a fresh instance of the same identity.
        self.seen_na = replay_cache if replay_cache is not None else set()
        self.epoch = 0
        self.tx = 0
        self.rx_j = 0
        self.rx = set()
        self.TH = b""
        self.peer = None
        self.sent_chain = None
        self.recv_chain = None
        self._hs_ek = self._hs_dk = None    # handshake KEM (ephemeral)
        self._ep_dk = None                  # refresh KEM secret (ephemeral)
        self.log = []

    # ---------------- phase 1 ----------------
    def initiate(self, peer_id):
        """A: eq 4-4, 4-5 -> M1 = (IDA, IDB, pkAe, NA, sigma_A)."""
        self.peer = peer_id
        self._hs_ek, self._hs_dk = kem_keygen()
        NA = os.urandom(NAN)
        self.state["NA"] = NA
        body = self.id + peer_id + self._hs_ek.to_bytes() + NA        # M1 (eq 4-4)
        sig = ibs.sign(self.mpk, self.sk_id, self.id, body)           # eq 4-5
        self.m1 = {"IDA": self.id, "IDB": peer_id, "pkAe": self._hs_ek.to_bytes(),
                   "NA": NA, "sigma": sig}
        return dict(self.m1)

    def respond(self, m1):
        """B: eq 4-6, 4-6a, 4-7, 4-8 -> M2, and derives the key schedule."""
        if m1["IDB"] != self.id:
            raise Error("M1 is not addressed to me")
        body = m1["IDA"] + m1["IDB"] + m1["pkAe"] + m1["NA"]
        if ibs.verify(self.mpk, m1["IDA"], body, m1["sigma"]) != 1:
            raise Error("Verify(params, IDA, M1, sigmaA) = 0 (eq 4-6)")
        # eq 4-6a: NA freshness, checked by the responder before any key material exists.
        if m1["NA"] in self.seen_na:
            raise Error("NA of this M1 was already used by a handshake I answered (replay)")
        self.seen_na.add(m1["NA"])
        NB = os.urandom(NAN)
        ct0, ss0 = kem_encaps(m1["pkAe"])                              # eq 4-7
        self.peer = m1["IDA"]
        self.state["ss0"] = ss0
        body2 = self.id + m1["IDA"] + NB + ct0 + m1["NA"]              # M2
        sig = ibs.sign(self.mpk, self.sk_id, self.id, body2)           # eq 4-8
        self.m2 = {"IDB": self.id, "IDA": m1["IDA"], "NB": NB, "ct0": ct0,
                   "NA": m1["NA"], "sigma": sig}
        self._schedule(m1["pkAe"], ct0, m1["NA"], NB, m1["sigma"], sig)
        return dict(self.m2)

    def finalize(self, m2):
        """A: eq 4-9, 4-10 + key schedule."""
        if m2["NA"] != self.state["NA"]:
            raise Error("NA mismatch: response to a handshake I never started")
        if self._hs_dk is None:
            raise Error("no pending handshake: skAe was already erased (eq 4-37)")
        body2 = m2["IDB"] + m2["IDA"] + m2["NB"] + m2["ct0"] + m2["NA"]
        if ibs.verify(self.mpk, m2["IDB"], body2, m2["sigma"]) != 1:
            raise Error("Verify(params, IDB, M2, sigmaB) = 0 (eq 4-9)")
        ss0 = kem_decaps(self._hs_dk, m2["ct0"])                        # eq 4-10
        self.state["ss0"] = ss0
        self.peer = m2["IDB"]
        self._schedule(self.m1["pkAe"], m2["ct0"], m2["NA"], m2["NB"],
                       self.m1["sigma"], m2["sigma"])
        self._hs_dk = None

    def _schedule(self, pkAe, ct0, NA, NB, sigA, sigB):
        ida = self.id if self.role == "initiator" else self.peer
        idb = self.peer if self.role == "initiator" else self.id
        self.TH = H(b"PQAKE Transcript", ida, idb, NA, NB, pkAe, ct0,
                    pack_sig(sigA), pack_sig(sigB))                     # eq 4-11
        salt0 = H(b"PQAKE-v1 Salt", ida, idb, NA, NB)                   # eq 4-12
        prk0 = HKDF_Extract(salt0, self.state["ss0"])                   # eq 4-13
        th = self.TH
        self.kra = HKDF_Expand(prk0, LAB_KRA + th)                      # eq 4-14
        rk0 = HKDF_Expand(prk0, LAB_RK + th)                            # eq 4-15
        self.state["RK"] = rk0
        self.state["Ksess"] = HKDF_Expand(prk0, LAB_SK + th)            # eq 4-16
        kconf = HKDF_Expand(prk0, LAB_KC + th)                          # eq 4-17
        cka = HKDF_Expand(prk0, LAB_CKA + th)                           # eq 4-18
        ckb = HKDF_Expand(prk0, LAB_CKB + th)                           # eq 4-19
        self.sent_chain, self.recv_chain = (cka, ckb) if self.role == "initiator" else (ckb, cka)
        self.kconf = kconf
        self.mac_b = hmac_bytes(kconf, th)                              # eq 4-20
        self.th1 = H(th, self.mac_b)
        self.mac_a = hmac_bytes(kconf, self.th1)
        self.epoch, self.tx, self.rx_j, self.rx = 0, 0, 0, set()

    def key_confirm(self, peer_mac):
        """MACB travels B->A, MACA travels A->B; both must match (eq 4-20/4-21)."""
        expect = self.mac_a if self.role == "responder" else self.mac_b
        if not consteq(peer_mac, expect):
            raise Error("key confirmation failed")
        return self.mac_b if self.role == "responder" else self.mac_a

    # ---------------- phase 2: asymmetric ratchet ----------------
    def start_epoch(self):
        e = self.epoch + 1
        ek, dk = kem_keygen()                                           # eq 4-24
        self._ep_dk = dk
        ad = self.id + self.peer + _u32(e) + self.TH                     # eq 4-25
        mac_a = hmac_bytes(self.kra, _u32(e) + ad + ek.to_bytes())        # eq 4-26
        self._msg_a = {"e": e, "AD": ad, "pke": ek.to_bytes(), "MACA": mac_a}
        return dict(self._msg_a)

    def accept_epoch_a(self, msg):
        if msg["e"] != self.epoch + 1:
            raise Error("refresh carries an out-of-order epoch number")
        want = self.peer + self.id + _u32(msg["e"]) + self.TH
        if msg["AD"] != want:
            raise Error("AD does not bind (IDA, IDB, e, TH_{e-1})")
        if not consteq(hmac_bytes(self.kra, _u32(msg["e"]) + msg["AD"] + msg["pke"]),
                       msg["MACA"]):
            raise Error("MAC_A invalid on refresh")
        ct, ss = kem_encaps(msg["pke"])                                  # eq 4-28
        mac_b = hmac_bytes(self.kra, _u32(msg["e"]) + msg["AD"] + ct + msg["MACA"])
        self._advance(msg["e"], msg["pke"], ct, ss)                      # eq 4-31..4-33
        return {"e": msg["e"], "AD": msg["AD"], "ct": ct, "MACB": mac_b}  # eq 4-29

    def accept_epoch_b(self, msg):
        if not consteq(hmac_bytes(self.kra, _u32(msg["e"]) + msg["AD"] + msg["ct"] +
                                  self._msg_a["MACA"]), msg["MACB"]):
            raise Error("MAC_B invalid on refresh")
        ss = kem_decaps(self._ep_dk, msg["ct"])                          # eq 4-30
        self._advance(msg["e"], self._msg_a["pke"], msg["ct"], ss)
        self._ep_dk = None

    def _advance(self, e, pke, ct, ss):
        ida = self.id if self.role == "initiator" else self.peer
        idb = self.peer if self.role == "initiator" else self.id
        self.TH = H(self.TH, _u32(e), pke, ct, ida, idb)                  # eq 4-31
        prk = HKDF_Extract(self.state["RK"], ss + _u32(e) + self.TH)      # eq 4-31
        self.state["RK"] = HKDF_Expand(prk, LAB_RK + self.TH)
        # eq 4-32/4-33 take their input from PRK_e, not from the stored root key: RK is kept
        # in session state for the next refresh, and a chain seeded from it would let a scrape
        # rebuild this epoch's message keys backwards (F5).
        send = HKDF_Expand(prk, LAB_SEND + _u32(e) + self.TH)
        recv = HKDF_Expand(prk, LAB_RECV + _u32(e) + self.TH)
        self.sent_chain, self.recv_chain = (send, recv) if self.role == "initiator" else (recv, send)
        self.epoch, self.tx, self.rx_j, self.rx = e, 0, 0, set()
        self.state["sse"] = ss
        self.log.append({"kind": "epoch", "e": e})

    # ---------------- phase 3: symmetric ratchet ----------------
    def encrypt(self, plaintext):
        e, j = self.epoch, self.tx
        ck = self.sent_chain
        mk = HKDF_Expand(ck, LAB_MK + _u32(e) + _u64(j))                   # eq 4-34
        self.sent_chain = HKDF_Expand(ck, LAB_NCK + _u32(e) + _u64(j))     # eq 4-35
        ad = self.id + self.peer + _u32(e) + _u64(j) + self.TH             # eq 4-36
        nonce = H(mk, b"nonce")[:12]
        ct = AESGCM(mk).encrypt(nonce, plaintext, ad)
        self.tx = j + 1
        self.log.append({"kind": "tx", "e": e, "j": j})
        return {"e": e, "j": j, "nonce": nonce, "ad": ad, "ct": ct}

    def decrypt(self, msg):
        e, j = msg["e"], msg["j"]
        if e != self.epoch:
            raise Error("message from epoch %d while in epoch %d" % (e, self.epoch))
        if (e, j) in self.rx:
            raise Error("replayed message (e=%d, j=%d)" % (e, j))
        if j < self.rx_j:
            raise Error("message counter went backwards (skipped key already erased)")
        while self.rx_j < j:                       # skip-ahead: erase intermediate keys
            self.recv_chain = HKDF_Expand(self.recv_chain,
                                          LAB_NCK + _u32(e) + _u64(self.rx_j))
            self.rx_j += 1
        mk = HKDF_Expand(self.recv_chain, LAB_MK + _u32(e) + _u64(j))
        self.recv_chain = HKDF_Expand(self.recv_chain, LAB_NCK + _u32(e) + _u64(j))
        self.rx_j = j + 1
        ad = self.peer + self.id + _u32(e) + _u64(j) + self.TH
        if not consteq(ad, msg["ad"]):
            raise Error("associated data mismatch")
        pt = AESGCM(mk).decrypt(msg["nonce"], msg["ct"], ad)
        self.rx.add((e, j))
        self.log.append({"kind": "rx", "e": e, "j": j})
        return pt

    # ---------------- exposure oracle ----------------
    def snapshot(self, level):
        s = {"RK": self.state.get("RK"), "send": self.sent_chain, "recv": self.recv_chain,
             "epoch": self.epoch, "TH": self.TH, "tx": self.tx, "rx_j": self.rx_j,
             "rx": set(self.rx)}
        if level == "message_state":
            return s
        if level == "session_state":
            s["Ksess"] = self.state.get("Ksess")
            return s
        if level == "kra":
            s.update({"KRA": self.kra, "sk_id": self.sk_id, "kconf": self.kconf})
            return s
        if level == "ephemeral":
            s["hs_dk"] = self._hs_dk
            s["ep_dk"] = self._ep_dk
            return s
        raise ValueError(level)


def _u32(x):
    return int(x).to_bytes(4, "little")


def _u64(x):
    return int(x).to_bytes(8, "little")
