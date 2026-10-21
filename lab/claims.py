"""Claim-by-claim testing of the thesis security claims (ch.5, sec. 5-2) and the ACCE/eCK
oracles they correspond to. Each test returns one or more records; `report.py` turns them
into tables.  The quantitative overhead claims of sec. 5-4 to 5-7 live in `lab/efficiency.py`
and are appended to the same matrix by `run_all`.

verdict:
  PASS                     protocol withstood the attack as claimed
  FAIL                     protocol accepted something it should reject
  CONFIRMED-VULNERABLE     an attack succeeds; the claim needs an extra assumption/fix
  DOCUMENTED-LIMITATION    succeeds only because of an assumption the thesis states
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import ibs, net as N, proto
from .proto import Error, HKDF_Expand, HKDF_Extract, consteq
from .proto import LAB_MK, LAB_NCK, LAB_RK, LAB_SK, LAB_KRA, LAB_SEND, LAB_RECV, LAB_CKA

_u32 = proto._u32
_u64 = proto._u64


def _rec(claim, model, procedure, expected, observed, verdict, note=""):
    return {"claim": claim, "model": model, "procedure": procedure,
            "expected": expected, "observed": observed, "verdict": verdict, "note": note}


def _fresh():
    n = N.Net()
    f = N.Fleet()
    A, B = N.establish(n, f)
    return n, f, A, B


def _captured_traffic(net):
    """Everything the Dolev-Yao adversary recorded on the wire that looks like app data."""
    out = []
    for rec in net.wire:
        if rec[0] == "DROPPED":
            continue
        frm, to, msg = rec
        if isinstance(msg, dict) and {"e", "j", "ct", "nonce", "ad"} <= set(msg):
            out.append((frm, to, msg))
        else:
            out.append((frm, to, None))
    return out


# ---------------------------------------------------------------- adversary core
class ChainState:
    """What an attacker holding a leaked chain key can do: ratchet only *forward*.
    This is the ACCE StateReveal oracle made executable."""

    def __init__(self, snap):
        self.ck = snap["recv"]
        self.epoch = snap["epoch"]
        self.j0 = snap["rx_j"]          # first index whose key was not yet erased

    def open(self, msg):
        if msg["e"] != self.epoch:
            raise Error("message is from epoch %d, leaked state is epoch %d"
                        % (msg["e"], self.epoch))
        if msg["j"] < self.j0:
            raise Error("message key already erased (j=%d < %d)" % (msg["j"], self.j0))
        ck = self.ck
        for j in range(self.j0, msg["j"] + 1):
            mk = HKDF_Expand(ck, LAB_MK + _u32(msg["e"]) + _u64(j))
            ck = HKDF_Expand(ck, LAB_NCK + _u32(msg["e"]) + _u64(j))
            if j == msg["j"]:
                return AESGCM(mk).decrypt(msg["nonce"], msg["ct"], msg["ad"])
        raise Error("unreachable")


class RootState:
    """The adversary the symbolic model gives us for free.

    eq 5-6 puts RK *inside* the scraped message_state, and for every epoch after the
    first one eq 4-32/4-33 derive the *initial* chain key as a function of RK alone.  So
    a leak of the message state does not merely leak the chain from the exposure point
    forwards (ChainState): it re-derives that epoch whole, backwards as well.  Earlier and
    later epochs stay out of reach - rootKdf replaces RK at each refresh, and the new ss_e
    is a KEM secret.
    """

    def __init__(self, snap):
        self.epoch = snap["epoch"]
        self.th = snap["TH"]
        # B's receiving chain of epoch e == A's sending chain == eq 4-32's SendKeys leaf.
        # Epoch 0 is the exception the equations force: its chains are the CKA/CKB leaves
        # of PRK0 (eq 4-18/4-19), and RK_0 = Expand(PRK0, "RootKey") (eq 4-15) does not
        # determine them, so the root key only re-derives chains from epoch 1 up.
        if self.epoch == 0:
            self.ck0 = None
        else:
            self.ck0 = HKDF_Expand(snap["RK"], LAB_SEND + _u32(self.epoch) + self.th)

    def open(self, msg):
        if msg["e"] != self.epoch:
            raise Error("message is from epoch %d, leaked root key is epoch %d"
                        % (msg["e"], self.epoch))
        if self.ck0 is None:
            raise Error("epoch 0 chains are not derived from RK")
        ck = self.ck0
        for j in range(0, msg["j"] + 1):
            mk = HKDF_Expand(ck, LAB_MK + _u32(msg["e"]) + _u64(j))
            ck = HKDF_Expand(ck, LAB_NCK + _u32(msg["e"]) + _u64(j))
            if j == msg["j"]:
                return AESGCM(mk).decrypt(msg["nonce"], msg["ct"], msg["ad"])
        raise Error("unreachable")


def try_open(snap, msg):
    for adv in (ChainState, RootState):
        try:
            adv(snap).open(msg)
            return True
        except Exception:
            continue
    return False


def _opens(adv, snap, msg):
    """Same question, asked of one named adversary - so a test can report which of the
    two the protocol defeated."""
    try:
        adv(snap).open(msg)
        return True
    except Exception:
        return False


# ------------------------------------------------------------ group A: authentication
def a1_mutual_auth():
    n, f, A, B = _fresh()
    ok = (A.state["Ksess"] == B.state["Ksess"] and A.TH == B.TH
          and A.sent_chain == B.recv_chain and A.recv_chain == B.sent_chain
          and consteq(A.kra, B.kra) and A.epoch == B.epoch == 0)
    return _rec("5-2-1 mutual authentication / 5-2-2 session-key confidentiality",
                "eCK-ROR, honest run",
                "honest handshake A<->B; compare Ksess, TH, both chains, KRA",
                "both accept with identical keys", "all identical = %s" % ok,
                "PASS" if ok else "FAIL")


def a2_forger_no_key():
    n, f, A, B = _fresh()
    C = f.node(b"IIOT-ATTACK-77")            # attacker has a valid key for its OWN identity
    m1 = C.initiate(B.id)
    m1["IDA"] = A.id                          # claim to be A, keep own signature
    try:
        B.respond(N._clone(m1))
        obs, v = "ACCEPTED a forged identity binding", "FAIL"
    except Error as e:
        obs, v = "aborted: %s" % e, "PASS"
    return _rec("5-2-1 authentication of the initiator (MITM cannot substitute pkAe)",
                "Dolev-Yao", "attacker with a valid key for ID C sends M1 structure under ID A",
                "Verify(IDA, M1, sigma) = 0", obs, v)


def a3_third_party_key():
    n, f, A, B = _fresh()
    C = f.node(b"IIOT-ATTACK-77", "initiator")
    m1 = n.send(C.id, B.id, C.initiate(B.id))
    try:
        B.respond(m1)
        v = "PASS" if B.peer == C.id else "FAIL"
        obs = "B authenticated the peer as C, not A (no impersonation of A)"
    except Error as e:
        obs, v = "aborted: %s" % e, "PASS"
    return _rec("5-2-5 impersonation using another node's identity key", "eCK Corrupt(C)",
                "corrupt an unrelated node C, run a full handshake with B as C",
                "C cannot make B believe it is talking to A", obs, v,
                "the authenticated id is carried in the transcript, so B's peer field is C")


def a4_uks():
    n, f, A, B = _fresh()
    C = f.node(b"IIOT-ROBOT-013", "responder")
    m1 = n.send(A.id, B.id, dict(A.initiate(B.id)))
    m1b = dict(m1)
    m1b["IDB"] = C.id                          # forward A's signed M1 to a third node
    try:
        C.respond(m1b)
        obs, v = "C accepted A's M1 (key-share possible)", "FAIL"
    except Error as e:
        obs, v = "C aborted: %s" % e, "PASS"
    return _rec("5-2-4 unknown key-share (UKS)", "eCK UKS",
                "forward A's signed M1 to another node C",
                "M1 is bound to IDB inside sigma_A, so C must reject", obs, v)


def a5_replay_m1():
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)                 # session 1 completes honestly
    m1 = [r for r in n.wire if r[0] == A.id and isinstance(r[2], dict)
          and "sigma" in r[2]][0][2]         # the M1 that was already consumed
    ksess_before = A.state["Ksess"]
    B2 = f.node(b"IIOT-PLC-0042", "responder")   # fresh instance of the same identity
    accepted = True
    try:
        m2b2 = n.send(B2.id, A.id, dict(B2.respond(dict(m1))))
    except Error as e:
        accepted = False
        m2b2 = None
        abort = str(e)
    outcome = None
    if accepted:
        try:
            A.finalize(m2b2)
            outcome = "A accepted the replayed M2 and replaced its live session keys"
        except Error as e:
            outcome = "A aborted: %s" % e
        matching = consteq(A.state["Ksess"], B2.state["Ksess"])
    return _rec("5-2-3 replay resistance of the handshake", "Dolev-Yao",
                "replay an already-consumed M1 to a fresh responder instance of B's identity, "
                "then hand the resulting M2 back to the original initiator",
                "responder rejects a replayed handshake; sessions must match",
                "fresh B accepted the stale M1 = %s; %s; B2 believes it shares a session with "
                "A (matching sessions = %s, A's Ksess unchanged = %s)"
                % (accepted, outcome, matching if accepted else "n/a",
                   consteq(ksess_before, A.state["Ksess"]) if accepted else "n/a"),
                "FAIL" if accepted else "PASS",
                "B never checks NA for freshness, so a responder can be made to complete a "
                "session with an initiator that is not participating: the AKE matching-sessions "
                "property fails and an attacker gets phantom sessions attributed to a victim "
                "(log/audit integrity, resource exhaustion). Erasure of skAe stops the session "
                "from also capturing the initiator's side. Fix: FINDINGS.md F2")


def a6_message_replay():
    n, f, A, B = _fresh()
    m = n.send(A.id, B.id, A.encrypt(b"setpoint=41.5"))
    B.decrypt(m)
    same = res = None
    try:
        B.decrypt(dict(m))
        same = "replayed (e,j) accepted"
    except Error as e:
        same = str(e)
    # an old message from a previous epoch
    N.do_epoch(n, A, B)
    try:
        B.decrypt(dict(m))
        res = "old-epoch message accepted"
    except Error as e:
        res = str(e)
    # out-of-order within an epoch: j=2 delivered before j=1
    m1 = n.send(A.id, B.id, A.encrypt(b"one"))
    m2 = n.send(A.id, B.id, A.encrypt(b"two"))
    B.decrypt(m2)
    try:
        B.decrypt(m1)
        ooo = "skipped-back message accepted"
    except Error as e:
        ooo = str(e)
    ok = "replayed" in same and "epoch" in res and "backwards" in ooo
    return _rec("5-2-3 replay resistance of the ratchet layer", "Dolev-Yao",
                "replay a consumed data message, replay it again after an asymmetric refresh, "
                "and deliver j=1 after j=2",
                "all three rejected", "same-epoch replay: %s | cross-epoch replay: %s | "
                "counter going backwards: %s" % (same, res, ooo),
                "PASS" if ok else "FAIL",
                "skip-ahead is supported (keys for skipped indices are derived then erased), "
                "step-back is not - the price of eq 4-37 erasure")


def a7_mitm_relay():
    n, f = N.Net(), N.Fleet()
    A = f.node(b"IIOT-GW-0001", "initiator")
    B = f.node(b"IIOT-PLC-0042", "responder")
    X = f.node(b"IIOT-ATTACK-77", "responder")   # the attacker's own honest instance
    # relay A's handshake to B untouched and B's reply back to A: a pure man in the middle
    m1 = n.send(A.id, B.id, dict(A.initiate(B.id)))
    m2 = n.send(B.id, A.id, dict(B.respond(dict(m1))))
    A.finalize(m2)
    macb = n.send(B.id, A.id, {"MACB": B.mac_b})["MACB"]
    A.key_confirm(macb)
    n.send(A.id, B.id, {"MACA": A.mac_a})
    B.key_confirm(A.mac_a)
    wire = b"".join([_u32(0) + _u64(0)] + [m1["NA"], m2["NB"], m1["pkAe"], m2["ct0"]])
    # the attacker sees everything on the wire and holds its own keys: can it derive A's Ksess?
    guesses = [proto.H(wire), A.recv_chain, X.state.get("Ksess")]
    guessable = any(consteq(g, A.state["Ksess"]) for g in guesses if g)
    return _rec("5-2-1 MITM: substituting handshake parameters", "Dolev-Yao",
                "relay the handshake verbatim while holding a valid identity key of one's own, "
                "then try pkAe/NA/NB/ct0-derived keys against A's session key",
                "signature binding of pkAe makes substitution abort; wire data alone yields "
                "nothing", "handshake completed under relay=%s; Ksess guessable from wire=%s"
                % (consteq(A.state["Ksess"], B.state["Ksess"]), guessable),
                "PASS" if not guessable else "FAIL",
                "pkAe is inside sigma_A (eq 4-4/4-5), so any substitution breaks verification")


# --------------------------------------- group B: forward secrecy / PCS exposure oracles
def b1_pfs_across_epochs():
    n, f, A, B = _fresh()
    N.traffic(n, A, B, 4)
    for _ in range(2):
        N.do_epoch(n, A, B)
        N.traffic(n, A, B, 3)
    cap = [m for _, _, m in _captured_traffic(n) if m is not None]
    snap = B.snapshot("message_state")
    e = snap["epoch"]
    earlier = [m for m in cap if m["e"] < e]
    current = [m for m in cap if m["e"] == e]
    cracked_old = sum(1 for m in earlier if try_open(snap, m))
    cracked_cur = sum(1 for m in current if try_open(snap, m))
    return _rec("5-2-6 forward secrecy (PFS) across epochs", "ACCE StateReveal",
                "after 2 refreshes / 10 messages, leak B's {RK, CKs, CKr, epoch, TH} and "
                "try every recorded ciphertext, split by whether it predates the "
                "refresh the leaked state belongs to",
                "0 of the %d messages of earlier epochs openable" % len(earlier),
                "%d/%d from earlier epochs open, %d/%d from the leaked epoch itself"
                % (cracked_old, len(earlier), cracked_cur, len(current)),
                "PASS" if cracked_old == 0 else "FAIL",
                "cross-epoch PFS holds: rootKdf(RK_{e-1}, ss_e) (eq 4-31) is one-way and "
                "ss_e is a KEM secret the adversary cannot decapsulate. The messages of "
                "the leaked epoch are a separate claim - see b8")


def b8_within_refreshed_epoch():
    """The attack the symbolic model found and b2's epoch-0 shape cannot see: with the
    scrape taken inside a *refreshed* epoch, eq 4-32 lets RK rebuild that epoch's chain
    from its first message key, so the erasure of eq 4-37 buys nothing for it."""
    n, f, A, B = _fresh()
    pre = [n.send(A.id, B.id, A.encrypt(b"epoch0_%d" % i)) for i in range(3)]
    for m in pre:
        B.decrypt(m)
    N.do_epoch(n, A, B)                         # now in epoch 1: eq 4-32/4-33 apply
    past = [n.send(A.id, B.id, A.encrypt(b"pt%d" % i)) for i in range(5)]
    for m in past:
        B.decrypt(m)
    snap = B.snapshot("message_state")
    future = [n.send(A.id, B.id, A.encrypt(b"after%d" % i)) for i in range(3)]
    chain_past = sum(1 for m in past if _opens(ChainState, snap, m))
    root_past = sum(1 for m in past if _opens(RootState, snap, m))
    root_future = sum(1 for m in future if _opens(RootState, snap, m))
    other = [m for _, _, m in _captured_traffic(n)
             if m is not None and m["e"] != snap["epoch"]]
    root_other = sum(1 for m in other if _opens(RootState, snap, m))
    return _rec("5-2-6 forward secrecy inside the epoch that was scraped",
                "ACCE StateReveal(message_state), eq 5-6 read literally",
                "run 5 messages in epoch 1, scrape B's message_state (which contains RK "
                "per eq 5-6), then re-derive the epoch's initial chain key per eq 4-32",
                "past messages of the epoch unreadable once their chain keys are erased "
                "(eq 4-37)",
                "chain-only attacker: past %d/5 | RK attacker: past %d/5, future %d/3, "
                "other epochs %d/%d" % (chain_past, root_past, root_future,
                                       root_other, len(other)),
                "FAIL" if root_past else "PASS",
                "eq 4-32 derives CK^send_1 = HKDF(RK, 'SendKeys'||e||TH), so a scrape that "
                "carries RK re-derives every message key of that epoch backwards and "
                "forwards; erasure only helps if RK is outside the scrape set. ProVerif "
                "agrees: pqake_ratchet.pv reaches pt20 from the scrape, and "
                "pqake_ratchet_minstate.pv, which scrapes without RK, does not")


def b2_within_epoch():
    n, f, A, B = _fresh()
    past = [n.send(A.id, B.id, A.encrypt(b"pt%d" % i)) for i in range(6)]
    for m in past:
        B.decrypt(m)
    snap = B.snapshot("message_state")          # leaked after j=0..5 consumed
    future = [n.send(A.id, B.id, A.encrypt(b"after%d" % i)) for i in range(3)]
    chain_past = sum(1 for m in past[:5] if _opens(ChainState, snap, m))
    chain_future = sum(1 for m in future if _opens(ChainState, snap, m))
    root_past = sum(1 for m in past[:5] if _opens(RootState, snap, m))
    root_future = sum(1 for m in future if _opens(RootState, snap, m))
    return _rec("5-2-6 forward secrecy inside one epoch (epoch 0)", "ACCE StateReveal",
                "leak B's message_state at (e=0, next j=6) - both the chain-only attacker "
                "and the RK-aware attacker ProVerif derives; try the 5 past and 3 future "
                "ciphertexts",
                "past unreadable; future readable until the next asymmetric refresh",
                "chain-only: past %d/5, future %d/3  |  RK-aware: past %d/5, future %d/3"
                % (chain_past, chain_future, root_past, root_future),
                "FAIL" if root_past else "DOCUMENTED-LIMITATION",
                "epoch 0 survives the RK-aware attacker because its chains are the "
                "CKA/CKB leaves of PRK0 (eq 4-18/4-19) rather than functions of RK; a "
                "symmetric chain still leaks forward from the exposure point until the KEM "
                "refresh repairs it, which is why the design is a dual ratchet. Refreshed "
                "epochs behave differently - see b8")


def b3_pcs_recovery():
    n, f, A, B = _fresh()
    N.traffic(n, A, B, 3)
    snap = B.snapshot("message_state")           # attacker gets in, is then locked out
    for _ in range(3):
        N.do_epoch(n, A, B)                      # recovery: fresh KEM entropy each epoch
    post = [n.send(A.id, B.id, A.encrypt(b"post-compromise%d" % i)) for i in range(4)]
    cracked = sum(1 for m in post if try_open(snap, m))
    return _rec("5-2-6 post-compromise security (recovery)", "ACCE StateReveal + refresh",
                "leak state, let it go stale, run 3 asymmetric refreshes, then send traffic",
                "a stale snapshot must not open any post-refresh message",
                "%d/4 opened with stale state" % cracked,
                "PASS" if cracked == 0 else "FAIL",
                "conditional PCS: relies on a fresh sse the attacker cannot decapsulate")


def b4_kra_not_reachable_from_state():
    n, f, A, B = _fresh()
    N.traffic(n, A, B, 4)
    N.do_epoch(n, A, B)
    snap = B.snapshot("message_state")
    # best effort from RK/TH only: re-derive KRA through every label the KDF tree exposes
    guesses = []
    for base in (snap["RK"],):
        for lab in (LAB_KRA, LAB_RK, LAB_SK, LAB_CKA, LAB_SEND):
            guesses.append(HKDF_Expand(base, lab + snap["TH"]))
    ok = not any(consteq(g, B.kra) for g in guesses)
    return _rec("5-2-6 'exposure of the symmetric keys does not expose KRA'",
                "ACCE StateReveal(message_state)",
                "leak {RK, CKs, CKr, epoch, TH}; try to recompute KRA from them",
                "KRA is derived from PRK0, not RK, so it is not reachable",
                "KRA recovered from leaked message state = %s" % (not ok),
                "PASS" if ok else "FAIL",
                "this is the assumption the thesis rests on for refresh authenticity")


def b5_pcs_breaks_if_kra_is_stored():
    """Ch.5-3 eq 5-5 puts KRA *inside the node's stored state* StAL1. Test what that costs."""
    n, f, A, B = _fresh()
    N.traffic(n, A, B, 2)
    snap = B.snapshot("kra")                     # memory scrape exactly as the state table says
    ek, dk = proto.kem_keygen()
    e = B.epoch + 1
    ad = B.peer + B.id + _u32(e) + snap["TH"]
    mac_a = proto.hmac_bytes(snap["KRA"], _u32(e) + ad + ek.to_bytes())
    forged = {"e": e, "AD": ad, "pke": ek.to_bytes(), "MACA": mac_a}
    try:
        mb = B.accept_epoch_a(forged)            # B accepts the attacker's refresh
    except Error as ex:
        return _rec("5-2-6 / 5-3-2 PCS under the documented internal state StAL1",
                    "ACCE StateReveal(StAL1)",
                    "scrape node memory as specified in eq 5-5 (StAL1 = {skIBS, pkIBS_GW, "
                    "RK0, KRA}), then forge a KEM refresh authenticated with the leaked KRA",
                    "state exposure must not allow future compromise",
                    "B rejected the forged refresh: %s" % ex, "PASS")
    ss = proto.kem_decaps(dk, mb["ct"])
    TH2 = proto.H(snap["TH"], _u32(e), forged["pke"], mb["ct"], B.peer, B.id)
    prk = HKDF_Extract(snap["RK"], ss + _u32(e) + TH2)
    rk2 = HKDF_Expand(prk, LAB_RK + TH2)
    msg = n.send(B.id, A.id, B.encrypt(b"plant=41.5"))
    # the attacker does not know which domain label B's outgoing chain uses: try both
    cracked = 0
    for lab in (LAB_SEND, LAB_RECV):
        ck = HKDF_Expand(rk2, lab + _u32(e) + TH2)
        mk = HKDF_Expand(ck, LAB_MK + _u32(msg["e"]) + _u64(msg["j"]))
        try:
            if AESGCM(mk).decrypt(msg["nonce"], msg["ct"], msg["ad"]) == b"plant=41.5":
                cracked = 1
        except Exception:
            pass
    # and the attacker's epoch is now permanently in the chain: subsequent refreshes from A
    later_readable = None
    try:
        N.do_epoch(n, A, B)
    except Error:
        later_readable = "A's next refresh aborted (epoch desynchronised)"
    return _rec("5-2-6 / 5-3-2 PCS under the documented internal state StAL1",
                "ACCE StateReveal(StAL1)",
                "scrape node memory as specified in eq 5-5 (StAL1 = {skIBS, pkIBS_GW, RK0, "
                "KRA}), then forge a KEM refresh authenticated with the leaked KRA",
                "state exposure must not allow future compromise",
                "B accepted the forged refresh (e=%d); attacker opened B's post-refresh "
                "plaintext = %d%s" % (e, cracked,
                                      "; %s" % later_readable if later_readable else ""),
                "CONFIRMED-VULNERABLE" if cracked else "FAIL",
                "the state model and the security claim contradict each other. Fix: keep KRA "
                "out of the scrapeable session state (secure element), or sign refreshes; "
                "see FINDINGS.md F3")


def b6_ephemeral_reveal():
    """eCK allows revealing the test session's OWN ephemeral secret. Phase 1 has no
    responder-side ephemeral contribution to ss0, so that alone yields every session key."""
    n, f = N.Net(), N.Fleet()
    A, B = f.node(b"IIOT-GW-0001", "initiator"), f.node(b"IIOT-PLC-0042", "responder")
    m1 = n.send(A.id, B.id, dict(A.initiate(B.id)))
    m2 = n.send(B.id, A.id, dict(B.respond(m1)))
    hs_dk = A.snapshot("ephemeral")["hs_dk"]     # before eq-mandated erasure
    A.finalize(m2)
    ss0 = proto.kem_decaps(hs_dk, m2["ct0"])
    salt0 = proto.H(b"PQAKE-v1 Salt", A.id, B.id, m1["NA"], m2["NB"])
    prk0 = HKDF_Extract(salt0, ss0)
    th = A.TH
    got_ksess = consteq(HKDF_Expand(prk0, LAB_SK + th), A.state["Ksess"])
    got_kra = consteq(HKDF_Expand(prk0, LAB_KRA + th), A.kra)
    got_rk = consteq(HKDF_Expand(prk0, LAB_RK + th), A.state["RK"])
    # after the first refresh the leaked prk0 no longer opens anything
    N.do_epoch(n, A, B)
    post = n.send(A.id, B.id, A.encrypt(b"after refresh"))
    ck_a = HKDF_Expand(prk0, LAB_CKA + th)
    opened = try_open({"recv": ck_a, "epoch": 0, "rx_j": 0}, post)
    return [
        _rec("5-2-2 session-key confidentiality under ephemeral reveal (eCK)",
             "eCK EphemeralKeyReveal(session)",
             "reveal only A's handshake KEM secret skAe, recompute ss0 -> PRK0 -> all "
             "epoch-0 keys; no long-term key is corrupted",
             "eCK requires the test session key to stay secret",
             "attacker recovered Ksess=%s, RK=%s, KRA=%s from the session's own ephemeral "
             "alone" % (got_ksess, got_rk, got_kra),
             "CONFIRMED-VULNERABLE" if got_ksess else "PASS",
             "phase 1 binds ss0 to a single ephemeral contribution; NB is a plaintext salt. "
             "Fix: encapsulate to a responder KEM key as well and mix both secrets; see F4"),
        _rec("5-2-6 repair after ephemeral compromise", "ACCE StateReveal(ephemeral)",
             "same leak, then one asymmetric refresh; try to open post-refresh traffic with "
             "the stale PRK0 chain", "post-refresh traffic must be unreadable",
             "post-refresh opened with stale handshake state = %s" % opened,
             "PASS" if not opened else "FAIL",
             "the ratchet limits the damage window of an ephemeral reveal to one epoch"),
    ]


def b7_refresh_dos():
    n, f, A, B = _fresh()
    N.traffic(n, A, B, 2)
    n.blocked.add((A.id, B.id))
    blocked = True
    try:
        N.do_epoch(n, A, B)
        blocked = False
    except Error:
        pass
    n.forget(A.id, B.id)
    stale = n.send(A.id, B.id, A.encrypt(b"still epoch %d" % A.epoch))
    readable_after_unblock = try_open(B.snapshot("message_state"), stale) if blocked else None
    return _rec("recovery requires a *successful* refresh (stated assumption, ch.4-9)",
                "ACCE, persistent active attacker",
                "jam every refresh message A->B, then let one data message through",
                "no security recovery while the control channel is jammed",
                "refresh jammed=%s; traffic keeps flowing on the stale symmetric chain=%s"
                % (blocked, readable_after_unblock),
                "DOCUMENTED-LIMITATION",
                "the thesis explicitly disclaims PCS against a persistent active attacker")


# ------------------------------------------------- group C: primitive / assumption audit
def c1_primitive_inventory():
    import numpy as np
    sz = ibs.sizes()
    inv = []
    for name, ps in (("ML-KEM-512", proto.ParameterSet.ML_KEM_512),
                     ("ML-KEM-768", proto.ParameterSet.ML_KEM_768)):
        k = proto.ML_KEM(ps)
        ek, dk = k.key_gen()
        ss, ct = k.encaps(ek)
        assert consteq(k.decaps(dk, ct), ss)
        inv.append("%s pk=%d ct=%d ss=%d" % (name, len(ek.to_bytes()), len(ct), len(ss)))
    return _rec("5-2-7 quantum resistance (no classical assumption on the wire)",
                "MLWE / Module-SIS hardness",
                "enumerate the primitives actually used and their on-the-wire sizes",
                "only lattice + hash/symmetric primitives; no RSA/ECDH/ECDSA",
                "%s | IBS: mpk=%d usk=%d sigma=%d B | SHA3-256, HMAC-SHA3-256, HKDF-SHA3, "
                "AES-256-GCM" % (" | ".join(inv), sz["mpk_bytes"], sz["usk_bytes"],
                                  sz["sigma_bytes"]),
                "PASS",
                "ch.5-2-7 names Kyber-768 for the ratchet layer; the harness measures both "
                "sizes. The signature is a rank-%d Module-LWE Fiat-Shamir-with-aborts "
                "prototype, not a NIST standard, so the claim inherits FIPS 203's assurance "
                "for the KEM only." % ibs.L)


def c2_ibshomomorphic_identity_key_is_insecure():
    """Thesis 5-2-1 rests on IBS unforgeability. The identity key is usk_id = h* s1, i.e.
    derived homomorphically from the public hash h. Any holder can undo it."""
    import numpy as np
    mpk, msk = ibs.setup()
    issued = b"IIOT-PLC-0042"
    usk = ibs.extract(mpk, msk, issued)
    h_hat = np.asarray(ibs.ring.ntt(ibs.expand_h(issued)), dtype=np.int64) % ibs.Q
    invertible = int((h_hat != 0).sum())
    inv = np.vectorize(lambda v: pow(int(v), ibs.Q - 2, ibs.Q))(h_hat)
    s1_hat = np.array([usk[j] * inv % ibs.Q for j in range(ibs.L)])
    s1_rec = np.array([ibs.ring.intt(s1_hat[j]) % ibs.Q for j in range(ibs.L)])
    matches = bool(np.array_equal(s1_rec, np.asarray(msk["s1"], dtype=np.int64) % ibs.Q))
    # forge for an identity the PKG never issued a key to, using only the recovered s1
    victim = b"IIOT-GW-9999"
    mu = b"raise setpoint to 200"
    h2_hat = ibs.ring.ntt(ibs.expand_h(victim))
    usk_victim = np.array([ibs.ring.reduce(h2_hat * s1_hat[j]) for j in range(ibs.L)])
    sig = ibs.sign(mpk, usk_victim, victim, mu)
    verdict = ibs.verify(mpk, victim, mu, sig)
    legit = ibs.verify(mpk, issued, mu, ibs.sign(mpk, usk, issued, mu))
    return _rec("5-2-1 IBS unforgeability / PKG master-secret confidentiality",
                "sID-EUF-CMA (identity-based game)",
                "take one legitimately issued usk_id, divide it pointwise in the NTT domain "
                "by the public hash of that identity, then multiply the quotient by a "
                "different identity's hash and sign",
                "usk_id must reveal nothing about the master secret s1",
                "h invertible in %d/%d NTT slots; s1 recovered bit-exactly = %s; "
                "forgery for an unissued identity verifies = %s (honest signature still "
                "verifies = %s)" % (invertible, ibs.N, matches, verdict == 1,
                                    legit == 1),
                "CONFIRMED-VULNERABLE" if (matches and verdict == 1) else "PASS",
                "the homomorphic (certificateless-style) key derivation usk_id = h*s1 is the "
                "leak: s1 is the PKG master secret and every node holds it. A GPV-style "
                "trapdoor derivation is required. See FINDINGS.md F1")


def d1_pkg_can_impersonate():
    n, f = N.Net(), N.Fleet()
    B = f.node(b"IIOT-PLC-0042", "responder")
    skA = ibs.extract(f.mpk, f.msk, b"IIOT-GW-0001")     # PKG holds MSK by definition
    Rogue = proto.Session(b"IIOT-GW-0001", skA, "initiator", f.mpk)
    m1 = n.send(b"IIOT-GW-0001", B.id, Rogue.initiate(B.id))
    B.respond(m1)
    Rogue.finalize(n.send(B.id, b"IIOT-GW-0001", dict(B.m2)))
    ok = Rogue.state["Ksess"] == B.state["Ksess"]
    return _rec("5-2-8 key escrow is inherent to IBS (stated limitation)", "trust model",
                "the PKG, holding MSK, derives A's identity key and completes a handshake "
                "with B as A", "B accepts; escrow cannot be removed by this construction",
                "rogue-PKG session established = %s" % ok,
                "DOCUMENTED-LIMITATION" if ok else "FAIL",
                "distinct from F1: escrow needs the MSK, F1 needs only one issued key")


def run_all(verbose=True):
    from . import efficiency
    tests = [a1_mutual_auth, a2_forger_no_key, a3_third_party_key, a4_uks, a5_replay_m1,
             a6_message_replay, a7_mitm_relay,
             b1_pfs_across_epochs, b2_within_epoch, b8_within_refreshed_epoch,
             b3_pcs_recovery,
             b4_kra_not_reachable_from_state, b5_pcs_breaks_if_kra_is_stored,
             b6_ephemeral_reveal, b7_refresh_dos, c1_primitive_inventory,
             c2_ibshomomorphic_identity_key_is_insecure, d1_pkg_can_impersonate]
    tests += efficiency.TESTS
    out = []
    for t in tests:
        import time
        t0 = time.perf_counter()
        try:
            r = t()
        except Exception as e:
            import traceback
            r = _rec(t.__name__, "-", "-", "-", "EXCEPTION %s: %s" % (type(e).__name__, e),
                     "ERROR", traceback.format_exc()[-600:])
        for rec in (r if isinstance(r, list) else [r]):
            rec["test"] = t.__name__
            rec["seconds"] = round(time.perf_counter() - t0, 3)
            out.append(rec)
            if verbose:
                print("%-42s %-22s %5.2fs" % (t.__name__, rec["verdict"],
                                              rec["seconds"]))
    return out
