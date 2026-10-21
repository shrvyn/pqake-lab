"""Claim-by-claim testing of the *quantitative* overhead claims of ch.5 (sections 5-4,
5-5, 5-6, 5-7): the byte counts of eq (11-5)/(12-5)/(13-5), tables 5-2/5-3/5-4, the memory
figures of 5-5, and the comparison against AKAME [4] / PiLike [8] / IBAKE [9] / PQ-Recon [3].

These are the claims the rest of the harness left untested: section 5-2's properties were
checked by attacks, but the efficiency claims were only ever *derived* in the thesis, never
measured.  Each test compares a figure the thesis states with a figure produced either by the
reference implementation (`lab/proto.py`, `lab/ibs.py`) or by the native C benchmark
(`c/ibs.c` and friends, recorded in results/perf.json).

verdicts:
  PASS                    thesis figure reproduced within the tolerance given in the note
  FAIL                    thesis figure is not what the implementation produces
  DOCUMENTED-LIMITATION   cannot be settled with the equipment available
"""
import contextlib
import json
import os

from . import ibs, net as N, perf as PERF, proto

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ------------------------------------------------------------- the thesis' own figures
THESIS = {
    # ch.5-4-1, eq (11-5) and the two substituted cases that follow it
    "setup_light_bytes": 2296,          # "light" tier, |sigma| = 300 B
    "setup_proposed_bytes": 6496,       # "proposed" tier, |sigma| = 2400 B
    "sigma_light": 300,
    "sigma_proposed": 2400,
    "sigma_dilithium2": 2420,           # ML-DSA-44, for the same formula
    # tables 5-2 (role split) and 5-3 (comparison), refresh + data rows
    "refresh_a_bytes": 816,             # pk 800 + MAC 16
    "refresh_b_bytes": 784,             # ct 768 + MAC 16
    "pcs_bytes": 1600,                  # entropy-injection round trip
    "per_message_bytes": 16,            # "fixed MAC"
    # table 5-3 competitor figures
    "akame_bytes": 4160,
    "pilike_bytes": 3860,
    # ch.5-5 storage
    "usk_assumed_bytes": 1024,
    "longterm_bytes": 1856,             # usk 1024 + reference pk 800 + KRA 32
    "ratchet_state_bytes": 104,         # RK + CKs + CKr + counters
    "node_total_bytes": 2048,           # "less than 2.0 kilobytes"
}

# The figures ch.5 states after this harness's measurements were folded back into it. Each
# test below asserts THIS table, so the amended thesis is what gets verified; the old figure
# stays in THESIS and in the note, which is what makes the correction auditable.
AMENDED = {
    "sigma_light": 1964,                # what ch.4-4's K=L=2 parameters actually produce
    "setup_light_bytes": 5594,
    "sigma_proposed": 2420,             # the high tier is priced with a standard ML-DSA-44
    "setup_proposed_bytes": 6506,
    "per_message_bytes": 109,
    "refresh_a_bytes": 897,
    "refresh_b_bytes": 865,
    "pcs_bytes": 1762,
    "usk_bytes": 1536,
    "longterm_bytes": 2368,
    "longterm_with_mpk_bytes": 3936,
    "ratchet_state_bytes": 180,
    "ratchet_state_with_kra_bytes": 212,
    "sram_budget_bytes": 48 * 1024,     # Cortex-M4 class, not the class-1 profile
}

_cache = {}


def _rec(claim, model, procedure, expected, observed, verdict, note=""):
    return {"claim": claim, "model": model, "procedure": procedure,
            "expected": expected, "observed": observed, "verdict": verdict, "note": note}


def _num(v):
    return "{:,}".format(int(round(v)))


def _perf_json():
    if "perf" not in _cache:
        p = os.path.join(_ROOT, "results", "perf.json")
        _cache["perf"] = json.load(open(p, encoding="utf-8")) if os.path.exists(p) else None
    return _cache["perf"]


def _cycles(scheme, op):
    """Measured mean cycles of one native operation, or None if it was not benchmarked."""
    pj = _perf_json()
    if not pj:
        return None
    for r in pj["native"]:
        if r["scheme"].startswith(scheme) and r["operation"] == op:
            return r["cycles_mean"]
    return None


def _wire():
    if "wire" not in _cache:
        _cache["wire"] = PERF.wire_sizes()
    return _cache["wire"]


def _state():
    if "state" not in _cache:
        _cache["state"] = PERF.state_footprint()
    return _cache["state"]


def _layout():
    """Byte length of every field the reference code actually transmits, per message type.

    `wire_sizes()` reports an analytic breakdown for some fields; this measures the objects,
    with the two integer counters encoded as the protocol would put them on the wire
    (epoch 4 B, message counter 8 B)."""
    if "layout" in _cache:
        return _cache["layout"]
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)
    ma = A.start_epoch()
    mb = B.accept_epoch_a(ma)
    A.accept_epoch_b(mb)
    data = A.encrypt(b"x" * 32)

    def size(msg):
        out = {}
        for k, v in msg.items():
            if k == "sigma":
                out[k] = len(proto.pack_sig(v))
            elif isinstance(v, (bytes, bytearray)):
                out[k] = len(v)
            elif isinstance(v, int):
                out[k] = 4 if k == "e" else 8
        return out

    lay = {"M1": size(A.m1), "M2": size(B.m2), "MsgA_refresh": size(ma),
           "MsgB_refresh": size(mb), "data_message": size(data)}
    for k, v in lay.items():
        v["TOTAL"] = sum(v.values())
    lay["sigma"] = lay["M1"]["sigma"]
    _cache["layout"] = lay
    return lay


# ---------------------------------------------------------------- operation counting
_PRIMS = {"kem_keygen": "KEM.KeyGen", "kem_encaps": "KEM.Encaps",
          "kem_decaps": "KEM.Decaps", "HKDF_Extract": "HKDF-Extract",
          "HKDF_Expand": "HKDF-Expand", "hmac_bytes": "HMAC", "H": "Hash",
          "AESGCM": "AEAD"}


@contextlib.contextmanager
def _counted(bucket):
    """Count calls to the primitive entry points of `proto` into `bucket`."""
    saved = {}

    def wrap(label, fn):
        def inner(*a, **k):
            bucket[label] = bucket.get(label, 0) + 1
            return fn(*a, **k)
        return inner

    for attr, label in _PRIMS.items():
        orig = getattr(proto, attr)
        saved[attr] = orig
        setattr(proto, attr, wrap(label, orig))
    for attr in ("sign", "verify"):
        orig = getattr(proto.ibs, attr)
        saved["ibs_" + attr] = orig
        setattr(proto.ibs, attr, wrap("IBS." + attr, orig))
    try:
        yield
    finally:
        for attr, orig in saved.items():
            if attr.startswith("ibs_"):
                setattr(proto.ibs, attr[4:], orig)
            else:
                setattr(proto, attr, orig)


def _fmt(d):
    return ", ".join("%s=%s" % (k, _num(v)) for k, v in sorted(d.items()))


def _asym(d):
    return {k: v for k, v in d.items() if k.startswith("KEM.") or k.startswith("IBS.")}


def e1_setup_overhead_light_tier():
    """ch.5-4-1 eq (11-5) as amended: the light tier IS the ch.4-4 instance, |sigma| = 1964 B."""
    lay = _layout()
    sig = lay["sigma"]
    measured = lay["M1"]["TOTAL"] + lay["M2"]["TOTAL"]
    meta = measured - 2 * sig
    ok = (measured == AMENDED["setup_light_bytes"] and sig == AMENDED["sigma_light"]
          and meta == AMENDED["setup_light_bytes"] - 2 * AMENDED["sigma_light"])
    return _rec(
        "5-4-1 eq (11-5): the light tier's setup phase costs 5594 B, with |sigma| = 1964 B "
        "and a 1666 B non-signature term",
        "byte accounting of the reference implementation",
        "rebuild eq (11-5) from the fields the reference code actually serialises (M1 + M2), "
        "separate the metadata term from the two signatures, and check the three numbers the "
        "amended section now prints",
        "5594 B",
        "metadata + KEM material = %s B, |sigma| = %s B, setup phase on the wire = %s B" % (
            _num(meta), _num(sig), _num(measured)),
        "PASS" if ok else "FAIL",
        "this row used to claim 2296 B at |sigma| = 300 B. Two corrections: the arithmetic "
        "constant is %d B, not the 1696 B the old substitution implied, and no 300 B signature "
        "comes out of ch.4-4 - the commitment (%s B at 6 bit/coeff) and the weight-%d challenge "
        "vector (%d B) already exceed 300 B before a response coefficient is sent, so the tier "
        "is priced with the signature the parameters actually produce. The equation itself is "
        "unchanged." % (meta, _num((ibs.K * ibs.N * 6 + 7) // 8), ibs.TAU,
                        ibs.TAU + (ibs.TAU + 7) // 8))


def e2_setup_overhead_proposed_tier():
    """ch.5-4-1 as amended: the high tier is priced with a standard ML-DSA-44 signature."""
    lay = _layout()
    sig = lay["sigma"]
    meta = lay["M1"]["TOTAL"] + lay["M2"]["TOTAL"] - 2 * sig
    with_ml_dsa = meta + 2 * AMENDED["sigma_proposed"]
    ok = with_ml_dsa == AMENDED["setup_proposed_bytes"]
    return _rec(
        "5-4-1: the proposed tier's setup phase costs 6506 B, i.e. 1666 B of material plus two "
        "2420 B ML-DSA-44 signatures",
        "byte accounting of the reference implementation",
        "the same reconstruction, substituting the standard signature the high tier names "
        "instead of an IBS of the same width",
        "6506 B",
        "with |sigma| = %s B the layout gives %s B; the identity-based signature of ch.4-4 "
        "would give %s B" % (_num(AMENDED["sigma_proposed"]), _num(with_ml_dsa),
                             _num(meta + 2 * sig)),
        "PASS" if ok else "FAIL",
        "the old row said 6496 B at |sigma| = 2400 B. The thesis' arithmetic was 30 B off the "
        "metadata constant and the 2400 B signature is not a published size either; the tier "
        "now names ML-DSA-44 (2420 B) and the total follows.")


def e3_per_message_overhead():
    """ch.5-4-1 eq (12-5) / table 5-3 as amended: a normal message carries 109 B of framing."""
    lay = _layout()["data_message"]
    plain = 32
    overhead = lay["TOTAL"] - plain
    ok = overhead == AMENDED["per_message_bytes"]
    return _rec(
        "5-4-1 eq (12-5) / table 5-3: a normal message costs 109 B of framing over its payload "
        "(epoch 4 + counter 8 + nonce 12 + bound context 69 + tag 16)",
        "byte accounting of the reference implementation",
        "serialise one ratchet-layer data message exactly as the reference code does and split "
        "the transmitted framing from the payload",
        "109 B",
        "%s B on the wire for a %d B payload = %s B of framing: epoch %s + counter %s + nonce "
        "%s + associated data %s + ciphertext+tag %s" % (
            _num(lay["TOTAL"]), plain, _num(overhead), _num(lay["e"]), _num(lay["j"]),
            _num(lay["nonce"]), _num(lay["ad"]), _num(lay["ct"])),
        "PASS" if ok else "FAIL",
        "the row read 16 B, which is the AEAD tag on its own. Eq 4-34..4-36 also put the epoch "
        "and message counters (needed for key skipping), the AES-GCM nonce and the AD that binds "
        "the message to (IDA, IDB, e, j, TH) on the wire; the amended figure counts all of it. "
        "On 802.15.4 with a 127 B MAC payload the difference between 16 B and 109 B of framing "
        "is the difference between one frame and two, so the section states it as two.")


def e4_refresh_and_pcs_overhead():
    """ch.5-4-1 eq (13-5) / tables 5-2, 5-3 as amended: 897 B + 865 B = 1762 B per refresh."""
    lay = _layout()
    ma, mb = lay["MsgA_refresh"], lay["MsgB_refresh"]
    trip = ma["TOTAL"] + mb["TOTAL"]
    ok = (ma["TOTAL"] == AMENDED["refresh_a_bytes"]
          and mb["TOTAL"] == AMENDED["refresh_b_bytes"]
          and trip == AMENDED["pcs_bytes"])
    return _rec(
        "5-4-1 eq (13-5) / tables 5-2 and 5-3: the asymmetric refresh costs 897 B + 865 B = "
        "1762 B round trip",
        "byte accounting of the reference implementation",
        "measure both refresh legs as the reference code emits them and account for the epoch "
        "number, the 61 B binding context and the lambda = 256 MAC that the KEM-only arithmetic "
        "leaves out",
        "1762 B",
        "A = %s B (epoch %s + AD %s + pk %s + MAC %s), B = %s B (epoch %s + AD %s + ct %s "
        "+ MAC %s) = %s B round trip" % (
            _num(ma["TOTAL"]), _num(ma["e"]), _num(ma["AD"]), _num(ma["pke"]),
            _num(ma["MACA"]), _num(mb["TOTAL"]), _num(mb["e"]), _num(mb["AD"]),
            _num(mb["ct"]), _num(mb["MACB"]), _num(trip)),
        "PASS" if ok else "FAIL",
        "the old figure was 816 + 784 = 1600 B: the KEM material plus a 16 B MAC. Eq 4-25/4-26 "
        "add a %d B epoch-binding context and a 4 B epoch number to each leg, and lambda = 256 "
        "makes the MAC %d B rather than 16 B - %d B per leg, %d B over the round trip." % (
            ma["AD"], ma["MACA"], ma["AD"] + ma["e"] + ma["MACA"] - 16,
            trip - THESIS["pcs_bytes"]))


def e5_comparison_with_other_schemes():
    """table 5-3 / ch.5-7 as amended: setup is heavier than [8]/[4]; the gain is cumulative."""
    lay = _layout()
    measured = lay["M1"]["TOTAL"] + lay["M2"]["TOTAL"]
    vs_pilike = 100.0 * (measured - THESIS["pilike_bytes"]) / THESIS["pilike_bytes"]
    vs_akame = 100.0 * (measured - THESIS["akame_bytes"]) / THESIS["akame_bytes"]
    ok = (measured == AMENDED["setup_light_bytes"]
          and measured > THESIS["pilike_bytes"] and measured > THESIS["akame_bytes"])
    return _rec(
        "5-7 / table 5-3: the light tier's setup phase (5594 B) is above PiLike [8] (3860 B) "
        "and AKAME [4] (4160 B), and the design's advantage is the cumulative one of e6",
        "byte accounting of the reference implementation",
        "put the measured handshake of this design on the same footing as the competitor "
        "figures quoted in table 5-3 and check the ordering the amended row states",
        "heavier at setup, lighter per message",
        "measured %s B = +%.0f%% against PiLike [8] (%s B) and +%.0f%% against AKAME [4] (%s B)"
        % (_num(measured), vs_pilike, _num(THESIS["pilike_bytes"]), vs_akame,
           _num(THESIS["akame_bytes"])),
        "PASS" if ok else "FAIL",
        "the row used to claim the opposite ordering, at 2296 B. The single-phase comparison "
        "genuinely goes against this design once the signature it actually produces is priced; "
        "what it wins is every later leg, which neither competitor has (the same table says "
        "they 'require re-running the key agreement'), so the comparison is stated per phase "
        "and summed in e6 rather than claimed in one snapshot.")


def e6_cumulative_vs_competitors():
    """Complete the comparison table's own logic: bytes over a whole session, not per phase."""
    lay = _layout()
    setup = lay["M1"]["TOTAL"] + lay["M2"]["TOTAL"]
    msg = lay["data_message"]["TOTAL"]
    refresh = lay["MsgA_refresh"]["TOTAL"] + lay["MsgB_refresh"]["TOTAL"]
    rows, verdict = [], "PASS"
    for k in (10, 100, 1000):
        ours = setup + k * msg + (k // 100) * refresh
        pilike = THESIS["pilike_bytes"] * k
        akame = THESIS["akame_bytes"] * k
        rows.append("k=%d: ours %s B, PiLike %s B, AKAME %s B" % (
            k, _num(ours), _num(pilike), _num(akame)))
        if k >= 100 and not (ours < pilike and ours < akame):
            verdict = "FAIL"
    return _rec(
        "5-7 / table 5-3, read cumulatively: this design beats schemes that must re-run the "
        "key agreement for every message",
        "byte accounting of the reference implementation",
        "price one session of k messages twice - this design (setup + k data messages + a "
        "refresh every 100 messages) against the competitor figures of table 5-3 multiplied "
        "by k, since those designs have no ratchet layer",
        "lower total bytes over a session",
        " | ".join(rows),
        verdict,
        "the ratchet is real and it is the claim worth keeping: setup is already %s B "
        "heavier than PiLike's single handshake, and the crossover is at k = %s messages, "
        "after which every additional message costs %s B here against %s B there. Table 5-3 "
        "as printed compares only the setup snapshot and therefore understates its own case. "
        "One honest caveat on the modelling: the competitor column prices 're-runs the key "
        "agreement' (the thesis' own words in that row) as a full setup handshake per "
        "message; a design that re-authenticates with a signature only would cost %s B per "
        "message instead and would push the crossover to k = %s." % (
            _num(setup - THESIS["pilike_bytes"]),
            _num(_crossover(setup, msg, refresh, THESIS["pilike_bytes"])),
            _num(msg), _num(THESIS["pilike_bytes"]), _num(THESIS["sigma_dilithium2"]),
            _num(_crossover(setup, msg, refresh, THESIS["sigma_dilithium2"] + 100))))


def _crossover(setup, msg, refresh, other):
    """Smallest k at which ours(k) < other(k), refreshing every 100 messages."""
    for k in range(1, 200000):
        if setup + k * msg + (k // 100) * refresh < other * k:
            return k
    return None


def e7_longterm_memory():
    """ch.5-5 as amended: 2368 B of long-term keys, 3936 B counting the group public key."""
    st = _state()
    usk, mpk = st["identity_key_bytes"], st["master_pk_bytes"]
    ours = usk + 800 + 32
    ok = (usk == AMENDED["usk_bytes"] and ours == AMENDED["longterm_bytes"]
          and ours + mpk == AMENDED["longterm_with_mpk_bytes"])
    return _rec(
        "5-5: long-term key memory is 2368 B (usk_id 1536 B + KEM public key 800 B + KRA 32 B) "
        "and 3936 B once the group public key a verifier must hold is counted",
        "byte accounting of the reference implementation",
        "measure the identity key and the group public key ch.4-4's parameters actually "
        "produce, then add the 800 B KEM public key and the 32 B KRA the thesis lists",
        "2368 B / 3936 B",
        "usk = %s B (L=%d vectors of n=%d coefficients at 3 B = %d*%d*3), own key + KEM pk + "
        "KRA = %s B, plus mpk = %s B gives %s B" % (
            _num(usk), ibs.L, ibs.N, ibs.L, ibs.N, _num(ours), _num(mpk), _num(ours + mpk)),
        "PASS" if ok else "FAIL",
        "the section said 1856 B, built on a 1024 B identity key. Ch.4-4's expansion is L "
        "vectors of n coefficients, 3 B per coefficient, so %d B; and the group public key was "
        "not counted at all although every Verify needs it. The 800 B KEM term was right."
        % usk)


def e8_ratchet_state_memory():
    """ch.5-5 as amended: 180 B of live session state, 212 B with KRA in RAM."""
    st = _state()
    ok = (st["per_session_node_bytes"] == AMENDED["ratchet_state_bytes"]
          and st["per_session_node_bytes_with_KRA"] == AMENDED["ratchet_state_with_kra_bytes"])
    return _rec(
        "5-5: the double ratchet needs 180 B of live session state, 212 B if KRA is kept in RAM "
        "alongside it",
        "byte accounting of the reference implementation",
        "count everything a running session must keep in order to send, receive, skip ahead and "
        "authenticate a refresh, per eq 4-11..4-36",
        "180 B / 212 B",
        "%s B as implemented, %s B with KRA in RAM. The state is RK, CK^send, CK^recv, TH, the "
        "epoch number, both message counters and the received-index set" % (
            _num(st["per_session_node_bytes"]), _num(st["per_session_node_bytes_with_KRA"])),
        "PASS" if ok else "FAIL",
        "104 B is reachable only by dropping the transcript binding, and that binding is what "
        "makes eq 4-26's refresh authentication and the UKS resistance of 5-2-4 work. The "
        "amended figure also states the KRA rule of 5-2-6: KRA belongs to the long-term key "
        "store, and the %d B figure is what a node pays if it keeps it in the session state "
        "instead - which is exactly the exposure eq 5-5 documents."
        % st["per_session_node_bytes_with_KRA"])


def e9_role_operation_sets():
    """table 5-2: A does KeyGen+Decaps+Sign+Verify+KDF, B does Encaps+Sign+Verify+KDF."""
    n, f = N.Net(), N.Fleet()
    A = f.node(b"IIOT-GW-0001", "initiator")
    B = f.node(b"IIOT-PLC-0042", "responder")
    a, b, a2 = {}, {}, {}
    with _counted(a):
        m1 = n.send(A.id, B.id, A.initiate(B.id))
    with _counted(b):
        m2 = n.send(B.id, A.id, B.respond(m1))
    with _counted(a2):
        A.finalize(dict(m2))
    a.update(a2)
    want_a = {"KEM.KeyGen": 1, "KEM.Decaps": 1, "IBS.sign": 1, "IBS.verify": 1}
    want_b = {"KEM.Encaps": 1, "IBS.sign": 1, "IBS.verify": 1}
    ok = (all(a.get(k, 0) == v for k, v in want_a.items()) and
          all(b.get(k, 0) == v for k, v in want_b.items()) and
          b.get("KEM.KeyGen", 0) == 0 and a.get("KEM.Encaps", 0) == 0)
    ca = {k: _cycles(s, o) or 0 for k, (s, o) in (
        ("KEM.KeyGen", ("ML-KEM-512", "keypair")), ("KEM.Decaps", ("ML-KEM-512", "decaps")),
        ("IBS.sign", ("IBS-K2L2", "sign")), ("IBS.verify", ("IBS-K2L2", "verify")))}
    cb = {k: _cycles(s, o) or 0 for k, (s, o) in (
        ("KEM.Encaps", ("ML-KEM-512", "encaps")),
        ("IBS.sign", ("IBS-K2L2", "sign")), ("IBS.verify", ("IBS-K2L2", "verify")))}
    ta, tb = sum(ca.values()), sum(cb.values())
    return _rec(
        "5-6 / table 5-2: phase-1 operation sets - initiator = TKeyGen+TDecaps+TSign+"
        "TVerify+TKDF, responder = TEncaps+TSign+TVerify+TKDF",
        "operation counting in the reference implementation, priced with native cycles",
        "instrument KEM.KeyGen/Encaps/Decaps, IBS.sign/verify, HKDF, HMAC, Hash and AEAD and "
        "drive the three handshake legs separately, attributing every call to the role that "
        "made it; then price each role's set with c/ibs.c and the ML-KEM-512 measurements",
        "A: 1 keygen, 1 decaps, 1 sign, 1 verify; B: 1 encaps, 1 sign, 1 verify, no keygen",
        "A = %s ; B = %s ; priced: A %s cycles, B %s cycles (A/B = %.2f)" % (
            _fmt(_asym(a)), _fmt(_asym(b)), _num(ta), _num(tb),
            ta / tb if tb else 0.0),
        "PASS" if ok else "FAIL",
        "the sets are exactly as table 5-2 says, and the asymmetry it implies is real but "
        "small: signing is %.0f%% of A's priced phase-1 cost and %.0f%% of B's, so the extra "
        "keygen that makes A 'heavier' moves the total by %.1f%%. The only lever this table "
        "leaves is A's ephemeral keygen (%s cycles), which an idle initiator could generate "
        "in advance; the responder already does no keygen." % (
            100.0 * ca["IBS.sign"] / ta if ta else 0.0,
            100.0 * cb["IBS.sign"] / tb if tb else 0.0,
            100.0 * (ta - tb) / tb if tb else 0.0, _num(ca["KEM.KeyGen"])))


def e10_no_asymmetric_work_per_message():
    """eq (16-5) / table 5-4: the data-message phase performs no asymmetric operation."""
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)
    bucket = {}
    msgs = 20
    with _counted(bucket):
        for _ in range(msgs):
            B.decrypt(A.encrypt(b"setpoint=41.5"))
    per = {k: v / float(msgs) for k, v in bucket.items()}
    asym = _asym(bucket)
    return _rec(
        "5-4-2 eq (16-5) / table 5-4: a normal message performs no asymmetric operation, "
        "reducing the cost from matrix multiplication to a constant KDF cost",
        "operation counting in the reference implementation",
        "count every primitive invoked while %d messages are sent and received inside one "
        "epoch" % msgs,
        "0 asymmetric operations per message",
        "%d asymmetric calls in %d message pairs; per message pair: %s" % (
            sum(asym.values()), msgs, _fmt(per)),
        "PASS" if not asym else "FAIL",
        "the design's strongest measured property, and it holds exactly: a message pair is "
        "4 HKDF-Expand + 1 hash + 2 AEAD contexts and nothing else (the HMAC column counts "
        "the PRF calls the KDF makes internally, one per expansion, so it is not additional "
        "work). Two caveats worth stating in the thesis: the 'constant' KDF cost is per "
        "message and per direction - 4 expansions, not the 2 that eq 4-34/4-35 suggest read "
        "one-way - and AES-256-GCM is not the lightweight choice the framing implies, since "
        "a hardware-less M0 has to run it in software.")


def e11_no_signature_in_refresh():
    """eq (17-5) / table 5-2: the refresh injects entropy with a KEM triple plus MACs, no "
    signatures."""
    n, f = N.Net(), N.Fleet()
    A, B = N.establish(n, f)
    bucket = {}
    with _counted(bucket):
        ma = A.start_epoch()
        mb = B.accept_epoch_a(ma)
        A.accept_epoch_b(mb)
    sigs = bucket.get("IBS.sign", 0) + bucket.get("IBS.verify", 0)
    kem = sum(_cycles("ML-KEM-512", o) or 0 for o in ("keypair", "encaps", "decaps"))
    hand = 2 * ((_cycles("IBS-K2L2", "sign") or 0) + (_cycles("IBS-K2L2", "verify") or 0)) + kem
    return _rec(
        "5-4-2 eq (17-5) / table 5-2: the asymmetric refresh removes Sign/Verify and costs "
        "one KEM triple plus HMACs",
        "operation counting in the reference implementation, priced with native cycles",
        "run one full epoch refresh - MsgA, MsgB and the return leg - with the primitive "
        "counters installed",
        "no IBS.sign / IBS.verify anywhere in the refresh",
        "%s -> sign+verify calls = %d" % (_fmt(bucket), sigs),
        "PASS" if sigs == 0 else "FAIL",
        "confirmed, and it is why the amortisation of section 5-4-2 works: a refresh is %s "
        "cycles of KEM where a re-handshake would be %s cycles. Of the %d HMAC calls, %d are "
        "the PRF inside the %d HKDF-Expand invocations and %d are the explicit "
        "eq 4-26/4-29 refresh tags - the MACs that replace the signatures. F3 (RESULTS.md, "
        "claim 17) shows what that trade costs if KRA is left in the state an attacker can "
        "scrape." % (_num(kem), _num(hand), bucket.get("HMAC", 0),
                     bucket.get("HMAC", 0) - bucket.get("HKDF-Expand", 0),
                     bucket.get("HKDF-Expand", 0),
                     bucket.get("HMAC", 0) - bucket.get("HKDF-Expand", 0)))


def e12_signing_cost_claim():
    """ch.5-7 / table 5-4 as amended: rank 2 wins on keygen and verify, loses on signing."""
    ibs_sign, d2_sign = _cycles("IBS-K2L2", "sign"), _cycles("Dilithium-2", "sign")
    ibs_vf, d2_vf = _cycles("IBS-K2L2", "verify"), _cycles("Dilithium-2", "verify")
    ibs_kg, d2_kg = _cycles("IBS-K2L2", "keypair"), _cycles("Dilithium-2", "keypair")
    if not ibs_sign or not d2_sign:
        return _rec(
            "5-7 / table 5-4: the rank-2 identity-based signature costs 72% of ML-DSA-44 to "
            "generate a key and 69% to verify, and 148% to sign",
            "native cycles (c/ibs.c on the Dilithium ring vs the Dilithium-2 reference)",
            "compare measured mean cycles of one accepted signature",
            "as stated per operation",
            "no native benchmark present - run c/build.sh, then python -c "
            "\"from lab import perf; perf.measure()\"",
            "DOCUMENTED-LIMITATION", "the claim was not testable at the time of this run")
    acc_p = (1.0 - 609.0 / 95232.0) ** 512
    acc_d2 = (1.0 - 78.0 / 95232.0) ** 1024
    kg, sg, vf = (100.0 * ibs_kg / d2_kg, 100.0 * ibs_sign / d2_sign, 100.0 * ibs_vf / d2_vf)
    ok = (abs(kg - 72) <= 2 and abs(vf - 69) <= 2 and abs(sg - 148) <= 3)
    return _rec(
        "5-7 / table 5-4: the rank-2 identity-based signature costs 72% of ML-DSA-44 for key "
        "generation and 69% for verification, but 148% for signing - the handshake is cheaper "
        "with a standard signature",
        "native cycles (c/ibs.c on the Dilithium ring vs the Dilithium-2 reference)",
        "compare measured mean cycles of one accepted signature, of one verification and of one "
        "key pair, on the same ring (n=256, q=8380417), same machine, with message-varying "
        "rejection loops in both",
        "72% / 69% / 148% of ML-DSA-44",
        "keygen %s cycles = %.0f%% of Dilithium-2's; verify %s = %.0f%%; sign %s = %.0f%% of "
        "a Dilithium-2 signature (%s)" % (
            _num(ibs_kg), kg, _num(ibs_vf), vf, _num(ibs_sign), sg, _num(d2_sign)),
        "PASS" if ok else "FAIL",
        "table 5-4 formerly argued that K = L = 2 makes the identity-based signature cheap "
        "enough to place in phase 1. The dimensional argument holds for keygen and verification "
        "and fails for signing: beta = (tau-1)*W_H*eta+1 = 609 against Dilithium's 78 puts the "
        "per-attempt acceptance at %.3f instead of %.3f, i.e. %.1f rejection attempts per "
        "signature against %.1f. The cost sits in the homomorphic key derivation, not in the "
        "ring, so any construction that keeps usk_id = h*s1 inherits it." % (
            acc_p, acc_d2, 1.0 / acc_p, 1.0 / acc_d2))


def e13_class1_mcu_feasibility():
    """ch.5-5 as amended: the footprint is a Cortex-M4-class budget, not a class-1 one."""
    st = _state()
    usk, mpk = st["identity_key_bytes"], st["master_pk_bytes"]
    keys = usk + 800 + 32
    total = keys + st["per_session_node_bytes"]
    with_mpk = total + mpk
    ok = (total == 2548 and with_mpk == 4116
          and 4 * with_mpk <= AMENDED["sram_budget_bytes"])
    return _rec(
        "5-5: the persistent footprint is 2548 B (4116 B with the group public key), which the "
        "section places on a Cortex-M4-class node with 48 kB of SRAM - not on a class-1 part",
        "capacity arithmetic from the reference implementation + pqm4's published M4 figures",
        "add up what a node must hold in RAM (identity key, KEM public key, KRA, session state, "
        "group public key) against the budget the amended section names, and read the handshake "
        "cost from pqm4",
        "4116 B against a 48 kB budget",
        "%s B of key material, %s B with the session state, %s B once the group public key the "
        "verifier must hold is counted - %.1f%% of a 48 kB budget, before code, stack, the NTT "
        "working buffers or the AES-GCM context" % (
            _num(keys), _num(total), _num(with_mpk), 100.0 * with_mpk / AMENDED["sram_budget_bytes"]),
        "PASS" if ok else "FAIL",
        "the section's conclusion used to read 'less than 2.0 kB, therefore runnable on class-1 "
        "Cortex-M0/M3 parts'. Its own byte counts refuse that: the persistent state alone is "
        "1.25x a 2 kB budget before a single byte of working memory, and pqm4 prices a full "
        "ML-KEM-512 + ML-DSA-44 handshake at about 498 ms on a Cortex-M4 with a refresh at 50.5 "
        "ms, so the amended text names the M4 class and states that the two phase-one signatures "
        "dominate; class-1 nodes stay on the ch.4-6 layer-1 profile, which stops after the KEM.")


TESTS = [e1_setup_overhead_light_tier, e2_setup_overhead_proposed_tier,
         e3_per_message_overhead, e4_refresh_and_pcs_overhead,
         e5_comparison_with_other_schemes, e6_cumulative_vs_competitors,
         e7_longterm_memory, e8_ratchet_state_memory, e9_role_operation_sets,
         e10_no_asymmetric_work_per_message, e11_no_signature_in_refresh,
         e12_signing_cost_claim, e13_class1_mcu_feasibility]
