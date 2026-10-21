"""Render RESULTS.md and FINDINGS.md from claims.json + results/perf.json + the vendored
pqm4 benchmark table. Run after run_claims.py and lab.perf.measure()."""
import csv
import json
import os
import time

HERE = os.path.dirname(os.path.abspath(__file__))
R = os.path.join(HERE, "results")
PQM4 = os.path.join(HERE, "vendor", "pqm4-src", "benchmarks.csv")

M4_MHZ = 24          # pqm4 README: "All cycle counts were obtained at 24MHz"


def load():
    claims = json.load(open(os.path.join(HERE, "claims.json"), encoding="utf-8"))
    perf = json.load(open(os.path.join(R, "perf.json"), encoding="utf-8"))
    return claims, perf


def pqm4_rows():
    """Pull the upstream Cortex-M4 cycle counts out of vendor/pqm4-src/benchmarks.csv."""
    out = {"kem": [], "sign": []}
    if not os.path.exists(PQM4):
        return out
    with open(PQM4, encoding="utf-8", errors="replace") as fh:
        rows = list(csv.reader(fh))
    mode = None
    for row in rows:
        if not row or not row[0]:
            continue
        joined = ",".join(row)
        if row[0] == "Scheme":
            if "Encapsulation [cycles]" in joined:
                mode = "kem"
            elif "Sign [cycles]" in joined:
                mode = "sign"
            else:
                mode = None          # memory / stack tables
            continue
        if mode is None or len(row) < 11:
            continue
        name = row[0].replace(" (10 executions)", "").replace(" (1000 executions)", "")
        if not name.startswith(("ml-kem", "ml-dsa")):
            continue
        try:
            rec = {"scheme": name, "impl": row[1], "kg": int(row[2])}
        except ValueError:
            continue
        if mode == "kem" and name.startswith("ml-kem"):
            rec.update(en=int(row[5]), de=int(row[8]))
            out["kem"].append(rec)
        elif mode == "sign" and name.startswith("ml-dsa"):
            rec.update(sg=int(row[5]), vf=int(row[8]))
            out["sign"].append(rec)
    keep = ("ml-kem-512", "ml-kem-768", "ml-dsa-44", "ml-dsa-65")
    out["kem"] = [r for r in out["kem"] if r["scheme"] in keep]
    out["sign"] = [r for r in out["sign"] if r["scheme"] in keep]
    return out


def ms(cycles):
    return "%.2f" % (cycles / (M4_MHZ * 1000.0))


def _cell(x):
    return str(x).replace("|", "/").replace("\n", " ")


def claim_table(claims):
    order = {"PASS": 0, "DOCUMENTED-LIMITATION": 1, "FAIL": 2,
             "CONFIRMED-VULNERABLE": 3, "ERROR": 4}
    lines = ["| # | claim (ch.5) | model / oracle | test procedure | observed | verdict |",
             "|---|---|---|---|---|---|"]
    for i, c in enumerate(sorted(claims["results"], key=lambda x: (order.get(x["verdict"], 9),
                                                                  x["test"])), 1):
        lines.append("| %d | %s | %s | %s | %s | **%s** |" % (
            i, _cell(c["claim"]), _cell(c["model"]), _cell(c["procedure"]),
            _cell(c["observed"]), c["verdict"]))
    return "\n".join(lines)


MODEL_NOTES = [
    ("pqake", "phase 1 as written (eq 4-4..4-21), honest long-term keys"),
    ("pqake_eck", "phase 1 + eCK EphemeralKeyReveal of the test session's own skAe"),
    ("pqake_pkg_escrow", "phase 1 after PKG master-secret compromise: every identity "
                         "secret key public (the consequence of F1 / D1)"),
    ("pqake_replay_fixed", "phase 1 + the F2 fix, a seenM1(id, NA) cache at the responder"),
    ("pqake_ratchet", "phases 2-3 (eq 4-23..4-37), StateReveal of the message state "
                      "exactly as eq 5-6 defines it"),
    ("pqake_ratchet_kra", "phases 2-3, StateReveal of the state as eq 5-5 literally stores "
                          "it, i.e. with KRA inside"),
    ("pqake_ratchet_minstate", "phases 2-3, the fix: scrape the chain keys but not RK"),
    ("limitation_table_else", "minimal reproduction of the tool limitation, not a protocol "
                              "claim: ProVerif cannot use a table read's negative branch "
                              "to prove injectivity"),
]


def formal_tables():
    """ProVerif verdicts, read straight out of model/logs/*.log so the table cannot drift
    from what the binary actually answered."""
    import re
    logdir = os.path.join(HERE, "model", "logs")
    if not os.path.isdir(logdir):
        return "_no model/logs - run `sh model/run_model.sh`_\n", 0
    lines = ["| model | what it models | statement | verdict |", "|---|---|---|---|"]
    total = 0
    for name, note in MODEL_NOTES:
        path = os.path.join(logdir, name + ".log")
        if not os.path.exists(path):
            continue
        verd = re.findall(r"^Query (.*) is (true|false)\.$",
                          open(path, encoding="utf-8").read(), re.M)
        for i, (q, v) in enumerate(verd):
            lines.append("| %s | %s | %s | **%s** |" % (
                name if i == 0 else "", _cell(note) if i == 0 else "", _cell(q), v))
            total += 1
    return "\n".join(lines), total


def native_table(perf):
    lines = ["| primitive | operation | cycles (min) | cycles (mean) | wall clock (mean) |",
             "|---|---|---|---|---|"]
    for r in perf["native"]:
        if r["operation"] in ("MISSING",):
            continue
        lines.append("| %s | %s | %s | %s | %s µs |" % (
            r["scheme"], r["operation"], "{:,.0f}".format(r["cycles_min"]),
            "{:,.0f}".format(r["cycles_mean"]), r["us_mean"]))
    return "\n".join(lines)


def ibs_estimate(perf):
    """Cross-check on the measured native IBS: reconstruct its cost by counting ring
    kernels in the numpy reference and pricing them with the measured kernels of section 3
    (same n = 256, same q = 8380417)."""
    kern = {r["operation"]: r["cycles_mean"] for r in perf["native"]
            if r["scheme"].startswith("ring")}
    if not kern:
        return "_ring kernel benchmark missing - run c/build.sh and re-measure_\n"
    tpu = 3290.0                      # ticks per microsecond, from the calibrated rdtsc runs
    ratios = [r["cycles_mean"] / r["us_mean"] for r in perf["native"]
              if r.get("us_mean") and r["cycles_mean"] > 500]
    if ratios:
        tpu = sum(ratios) / len(ratios)
    ops = perf["py_ibs"]["ops"]
    att = perf["py_ibs"].get("attempts_mean", 1.0)
    missing = [k for k in ("poly_ntt", "poly_invntt_tomont", "poly_basemul_montgomery",
                           "poly_uniform", "poly_uniform_gamma1", "polyz_pack",
                           "shake128_128B_out") if k not in kern]
    if missing:
        return "_ring kernel benchmark lacks %s - run c/build.sh and re-measure_" % ", ".join(missing)
    est = {}
    for pref in ("sign", "verify"):
        parts, total = [], 0.0
        for mult, name in ((ops["ntt_per_" + pref], "poly_ntt"),
                           (ops["intt_per_" + pref], "poly_invntt_tomont"),
                           (ops["basemul_per_" + pref], "poly_basemul_montgomery")):
            total += mult * kern[name]
            parts.append("%d x %s" % (mult, name))
        n_extra, extra = {"sign": (ops["K"], "poly_uniform_gamma1"),
                          "verify": (ops["K"], "polyz_pack")}[pref]
        total += n_extra * kern[extra]
        parts.append("%d x %s" % (n_extra, extra))
        total += 4 * kern["shake128_128B_out"]
        parts.append("4 x shake128(128B)")
        a_exp = ops["K"] * ops["L"] * (kern["poly_uniform"] + kern["poly_ntt"])
        expected = total * (att if pref == "sign" else 1.0) + a_exp
        est[pref] = (total, "; ".join(parts), a_exp, expected)
    lines = ["Kernel-price reconstruction of the numpy reference (K=L=%d, n=%d, q=%d), "
             "priced with the dilithium-ring kernels of section 3:"
             % (ops["K"], ops["N"], ops["q"]), "",
             "| IBS operation | kernels per rejection attempt | cycles/attempt | "
             "A expansion | expected total | expected wall clock |",
             "|---|---|---|---|---|---|"]
    for side in ("sign", "verify"):
        total, parts, a_exp, expected = est[side]
        lines.append("| %s | %s | %s | %s | %s | %.0f µs |" % (
            side, parts, "{:,.0f}".format(total), "{:,.0f}".format(a_exp),
            "{:,.0f}".format(expected), expected / tpu))
    lines.append("\n`A expansion` = K x L x (poly_uniform + poly_ntt): the C implementation "
                 "re-expands the matrix from rho inside every sign and verify (the Dilithium "
                 "reference convention, where rho travels in the key), the numpy reference "
                 "caches A_hat in the public key and therefore does not pay it. "
                 "For sign the total is multiplied by the %.1f expected rejection attempts; "
                 "verify has no rejection loop." % att)
    d2 = [r for r in perf["native"] if r["scheme"].startswith("Dilithium-2")
          and r["operation"] == "sign"]
    if d2:
        lines.append("\nReconstructed this way, one signature is %.0f%% of a measured "
                     "Dilithium-2 signature (%s cycles mean, section 3) even though the "
                     "prototype runs K=L=2 instead of K=L=4: the rejection loop, not the "
                     "ring arithmetic, is what sets the price. Section 8 deviation 5 and "
                     "the note under the table above give the reason - our beta is 609 "
                     "instead of Dilithium's 78, so the commitment abort costs ~27 attempts "
                     "instead of the ~2.3 that the same formula predicts for Dilithium-2."
                     % (100.0 * est["sign"][3] / d2[0]["cycles_mean"],
                        "{:,.0f}".format(d2[0]["cycles_mean"])))
    meas = [r for r in perf["native"] if r["scheme"] == "IBS-K2L2"
            and r["operation"] == "sign"]
    if meas and est["sign"][3]:
        d = perf.get("ibs_selftest", {}).get("dist", {})
        lines.append("\nReconstruction versus measurement: `c/ibs.c` signs in %s cycles, "
                     "%.0f%% above the kernel price computed above. The gap is not hidden "
                     "work in the ring, it is two things the table deliberately leaves out - "
                     "the measured rejection average is %.2f attempts on this run where the "
                     "table multiplies by the analytic %.1f, and the portable C carries "
                     "coefficient-wide passes the kernel list does not price (poly_reduce "
                     "after every accumulated term, ibs_decompose, pack_w, and the "
                     "poly_center + running max-abs scans that produce the abort "
                     "statistics). Treat the reconstruction as a lower bound on any honest "
                     "implementation and the measured row as the claim." % (
                         "{:,.0f}".format(meas[0]["cycles_mean"]),
                         100.0 * (meas[0]["cycles_mean"] / est["sign"][3] - 1.0),
                         d.get("attempts_mean", att), att))
    return "\n".join(lines)


def ibs_section(perf):
    """Chapter 4-4's identity-based signature, now measured natively (c/ibs.c on the
    Dilithium ring kernels) with the kernel-count estimate kept as a cross-check."""
    rows = {r["operation"]: r for r in perf["native"] if r["scheme"] == "IBS-K2L2"}
    if not rows:
        return "_native IBS benchmark missing - run c/build.sh and re-measure_\n"
    lines = []
    st = perf.get("ibs_selftest", {})
    if st.get("log"):
        lines.append("Self-test of `c/bench_ibs.exe`, which runs these checks before it "
                     "measures (process exit code %s):" % st["rc"])
        lines.extend("* %s" % l for l in st["log"])
        lines.append("")
    d2 = {r["operation"]: r for r in perf["native"]
          if r["scheme"].startswith("Dilithium-2")}
    d3 = {r["operation"]: r for r in perf["native"]
          if r["scheme"].startswith("Dilithium-3")}
    lines.append("| operation | IBS K=L=2 (cycles) | IBS (wall) | vs Dilithium-2 | "
                 "vs Dilithium-3 |")
    lines.append("|---|---|---|---|---|")
    for op, lbl in (("keypair", "keygen"), ("extract", "extract (PKG)"),
                    ("sign", "sign"), ("verify", "verify")):
        if op not in rows:
            continue
        r = rows[op]
        ratio = lambda tab, key: ("%.0f%%" % (100.0 * r["cycles_mean"] / tab[key]["cycles_mean"])
                                  if tab.get(key) else "-")
        lines.append("| %s | %s | %.1f µs | %s | %s |" % (
            lbl, "{:,.0f}".format(r["cycles_mean"]), r["us_mean"],
            ratio(d2, op), ratio(d3, op)))
    lines.append("\n" + ibs_estimate(perf))

    def rel(op):
        if not rows.get(op) or not d2.get(op):
            return float("nan")
        return 100.0 * rows[op]["cycles_mean"] / d2[op]["cycles_mean"]

    g2, beta_proto, beta_d2 = 95232.0, 609.0, 78.0
    acc_proto = (1.0 - beta_proto / g2) ** 512      # K*n = 2*256 coefficients
    acc_d2 = (1.0 - beta_d2 / g2) ** 1024           # Dilithium-2: K*n = 4*256
    lines.append(
        "\nRead the two blocks together, because the honest headline is uncomfortable: "
        "keygen and verify do come out below Dilithium-2 (%.0f%% and %.0f%% of its measured "
        "cost) as the K=L=2 versus K=L=4 argument predicts, but sign does not - it is "
        "%.0f%% of a Dilithium-2 signature. The reason is the abort rate, not the "
        "arithmetic. The commitment test keeps a signature only if "
        "|LowBits(Ay)| <= gamma_2 - beta over every K*n coefficient, so the per-attempt "
        "acceptance is (1 - beta/gamma_2)^(K*n) = %.3f for this prototype "
        "(beta = (tau-1)*W_H*eta + 1 = 609, K*n = 512) against %.3f for Dilithium-2 "
        "(beta = 78, K*n = 1024): %.1f attempts instead of %.1f. The factor that makes the "
        "difference is the identity element itself - multiplying the master secret by a "
        "public, weight-8 sparse polynomial is exactly what turns beta = tau*eta into "
        "beta = (tau-1)*W_H*eta + 1. So the identity-based derivation costs this protocol "
        "more than a Dilithium-2 signature per phase-1 authentication even before F1 asks "
        "whether it is secure at all, and any patched variant that keeps a homomorphic "
        "(scalar-multiple) key derivation inherits the same abort rate. Section 8, "
        "deviation 5 records the second half of the same story: the response-norm abort "
        "never fires at all in this parameter set." % (
            rel("keypair"), rel("verify"), rel("sign"),
            acc_proto, acc_d2, 1.0 / acc_proto, 1.0 / acc_d2))
    return "\n".join(lines)


def session_totals(perf, msgs=1000):
    """End-to-end cost of one session of `msgs` authenticated messages, priced with the
    native cycles of section 3 and the wire bytes of section 5, for several refresh
    cadences and for the obvious alternative signature choice."""
    cy = {}
    for r in perf["native"]:
        cy[(r["scheme"].split(" ")[0], r["operation"])] = r["cycles_mean"]

    def c(scheme, op):
        for (s, o), v in cy.items():
            if o == op and s.startswith(scheme):
                return v
        return 0.0

    tpu = next((r["cycles_mean"] / r["us_mean"] for r in perf["native"]
                if r["scheme"].startswith("ML-KEM") and r["operation"] == "encaps"), 3290.0)
    kg, en, de = (c("ML-KEM-512", "keypair"), c("ML-KEM-512", "encaps"),
                  c("ML-KEM-512", "decaps"))
    refresh = kg + en + de
    hs_ibs = 2 * (c("IBS-K2L2", "sign") + c("IBS-K2L2", "verify"))
    hs_dil = 2 * (c("Dilithium-2", "sign") + c("Dilithium-2", "verify"))
    hs_kem = kg + en + de
    w = perf["wire"]
    hs_bytes = w["M1"]["bytes"] + w["M2"]["bytes"]
    rf_bytes = w["MsgA_refresh"]["bytes"] + w["MsgB_refresh"]["bytes"]
    msg_bytes = w["data_message"]["bytes"]
    lines = ["| configuration (session of %d messages) | phase-1 signatures | refreshes | "
             "asymmetric cycles | asymmetric wall clock | handshake bytes | session bytes |"
             % msgs,
             "|---|---|---|---|---|---|---|"]
    for label, cad, hs in (("PQAKE-v1, refresh every %d messages" % 1, 1, hs_ibs),
                           ("PQAKE-v1, refresh every 100 messages", 100, hs_ibs),
                           ("PQAKE-v1, refresh every 1000 messages", 1000, hs_ibs),
                           ("same schedule, ML-DSA-44-class signature instead of the IBS",
                            100, hs_dil)):
        nref = msgs // cad
        total = hs + hs_kem + nref * refresh
        byte_total = hs_bytes + nref * rf_bytes + msgs * msg_bytes
        lines.append("| %s | %d | %d | %s | %.1f ms | %d | %d |" % (
            label, 2, nref, "{:,.0f}".format(total), total / tpu / 1000.0,
            hs_bytes, byte_total))
    lines.append("\nOnly the two asymmetric columns react to the cadence; the bytes columns "
                  "are dominated by the per-message AEAD ciphertext (%d B each, section 5), "
                  "and the compute behind them is symmetric-only "
                  "(2 HKDF-Expand + 1 AEAD seal + hashes per message, priced in section 7). "
                  "The last row is the point of ch.4-4: replacing the prototype's "
                  "identity-based signature with a plain Dilithium-2 key would make the "
                  "handshake %s cycles %s (%.1f ms on this machine) - the K=L=2 versus "
                  "K=L=4 argument is beaten by the abort rate - and would remove finding "
                  "F1, so the signature layer is where both the cost and the break live.\n" % (
                      msg_bytes, "{:,.0f}".format(abs(hs_dil - hs_ibs)),
                      "cheaper" if hs_dil < hs_ibs else "more expensive",
                      abs(hs_dil - hs_ibs) / tpu / 1000.0))
    return "\n".join(lines)


def m4_table(rows):
    lines = ["| scheme (Cortex-M4, pqm4) | impl | keygen cycles | encaps/Sign cycles | "
             "decaps/Verify cycles | keygen @24MHz | encaps/Sign @24MHz | decaps/Verify @24MHz |",
             "|---|---|---|---|---|---|---|---|"]
    for r in rows["kem"]:
        lines.append("| %s | %s | %s | %s | %s | %s ms | %s ms | %s ms |" % (
            r["scheme"], r["impl"], "{:,}".format(r["kg"]), "{:,}".format(r["en"]),
            "{:,}".format(r["de"]), ms(r["kg"]), ms(r["en"]), ms(r["de"])))
    for r in rows["sign"]:
        lines.append("| %s | %s | %s | %s | %s | %s ms | %s ms | %s ms |" % (
            r["scheme"], r["impl"], "{:,}".format(r["kg"]), "{:,}".format(r["sg"]),
            "{:,}".format(r["vf"]), ms(r["kg"]), ms(r["sg"]), ms(r["vf"])))
    return "\n".join(lines)


def wire_table(perf):
    w = perf["wire"]
    lines = ["| message | total bytes | breakdown |", "|---|---|---|"]
    for k, v in w.items():
        if not isinstance(v, dict):
            continue
        parts = ", ".join("%s=%s" % (a, b) for a, b in v["components"].items())
        lines.append("| %s | %d | %s |" % (k, v["bytes"], parts))
    return "\n".join(lines)


def cadence_table(perf):
    lines = ["| refresh every k messages | KEM keygen | KEM encaps | KEM decaps | "
             "HKDF-Expand | AEAD seal | hash+mac ops |",
             "|---|---|---|---|---|---|---|"]
    for r in perf["ops_per_message"]:
        lines.append("| %d | %.4f | %.4f | %.4f | %.2f | %d | %d |" % (
            r["refresh_cadence_msgs"], r["kem_keygen_per_msg"], r["kem_encaps_per_msg"],
            r["kem_decaps_per_msg"], r["hkdf_expand_per_msg"], r["aead_seal"],
            r["sha3"]))
    return "\n".join(lines)


def py_table(perf):
    rows = []
    for group in ("py_symmetric", "py_kem", "py_ibs", "py_protocol"):
        for k, v in perf[group].items():
            if not isinstance(v, dict) or "us_mean" not in v:
                continue
            rows.append("| %s | %s | %s µs | %s µs | %d |" % (
                group.replace("py_", ""), k, "{:,.1f}".format(v["us_mean"]),
                "{:,.1f}".format(v["us_min"]), v["iters"]))
    return ("| layer | operation | mean | min | iterations |\n|---|---|---|---|---|\n"
            + "\n".join(rows))


def results_md(claims, perf, rows):
    tally = {}
    for c in claims["results"]:
        tally[c["verdict"]] = tally.get(c["verdict"], 0) + 1
    st = perf.get("ibs_selftest", {}).get("dist", {})
    ibs_c = {r["operation"]: r["cycles_mean"] for r in perf["native"]
             if r["scheme"] == "IBS-K2L2"}
    ibs_c_sign = ibs_c.get("sign", 0.0)
    d2sign = next((r["cycles_mean"] for r in perf["native"]
                   if r["scheme"].startswith("Dilithium-2") and r["operation"] == "sign"), 0)
    body = []
    A = body.append
    A("# PQAKE-v1: implementation and security-claim test results\n")
    A("Generated %s from `run_claims.py` and `lab.perf.measure()`.\n" % claims["generated"])
    A("## 1. Method and environment\n")
    A("* Reference implementation of ch.4 equation by equation: `lab/proto.py` "
      "(phase 1 eq 4-4..4-21, asymmetric ratchet eq 4-23..4-33, message ratchet "
      "eq 4-34..4-37), active Dolev-Yao channel + ACCE exposure oracle: `lab/net.py`, "
      "`Session.snapshot(level)`.")
    A("* Identity-based signature: `lab/ibs.py` + `lab/ring.py` (negacyclic NTT over "
      "R_q = Z_q[X]/(X^256+1), q=8380417, K=L=2, gamma_1=2^17, gamma_2=95232, tau=39, "
      "eta=2), validated against a naive polynomial reference and an exhaustive "
      "decomposition sweep (`test_ibs.py`), and implemented a second time in C on the "
      "vendored Dilithium ring kernels (`c/ibs.c` -> `c/bench_ibs.exe`): the two "
      "implementations use different XOF layouts, so agreement on sign/verify, on the "
      "negative tests and on the rejection rate is a cross-check rather than a "
      "restatement.")
    A("* ML-KEM: FIPS 203 code (`mlkem` wheel, Rust) inside the functional harness and the "
      "pq-crystals reference C compiled natively for timings (`c/bench_kem.c`).")
    A("* Toolchain: laptop only. Zig 0.17 used as an x86-64 C compiler, "
      "-O3 -march=native; cycles via rdtsc, calibrated against CLOCK_MONOTONIC.")
    A("* pqm4: vendored at `vendor/pqm4-src` (mupq/pqm4). Its per-algorithm kernels are "
      "Cortex-M4 assembly (poly_asm.S, ntt routines written as `.S`/`.i` macros) and cannot "
      "be compiled for x86, and no M4 board or qemu-icount setup is available here. What "
      "pqm4 does give us off the shelf is its published cycle table, reproduced below.\n")
    A("## 2. Claim x test x verdict\n")
    A("Totals: " + ", ".join("%s = %d" % (k, v) for k, v in sorted(tally.items())) + "\n")
    A(claim_table(claims))
    A("\n## 2b. Symbolic verification: ProVerif 2.05, executed\n")
    A("Same properties, exhaustive Dolev-Yao adversary over the free algebra. ProVerif "
      "2.05 (official Inria Windows binary) vendored at `vendor/proverif2.05/`; models in "
      "`model/*.pv`, raw transcripts in `model/logs/`, re-run with `sh model/run_model.sh`. "
      "Interpretation guide: a `not attacker(X)` verdict of *false* means the tool found a "
      "concrete attack; an implication `event(...) ==> event(...)` of *false* means a "
      "correspondence (aliveness / agreement) is violated. The reading of each line, "
      "including the two cases where a *false* is a limitation of the tool rather than of "
      "the protocol, is in `model/ACCE-PQAKE.md` sections 4 and 7.\n")
    ftab, nq = formal_tables()
    A(ftab)
    A("\n%d query verdicts over the %d model files above; %d of them are protocol models and "
      "the last is the tool-limitation reproduction. Four verdicts re-establish what the "
      "harness found (F2 uniqueness, F3 with KRA in the state, F4 with the ephemeral reveal, "
      "and the consequence of F1: all seven phase-1 statements fail once the identity keys "
      "are public), and one is new: the within-epoch break of F5, which the harness's weaker "
      "attacker had passed.\n" % (nq, len(MODEL_NOTES), len(MODEL_NOTES) - 1))
    A("\n## 3. Native primitive timings (this laptop, x86-64)\n")
    A(native_table(perf))
    A("\nCycles are invariant-TSC ticks; the core runs at a different clock, so wall clock "
      "is measured independently and both are reported.\n")
    A("### 3b. Identity-based signature of ch.4-4: measured natively, and reconstructed "
      "from the measured ring kernels\n")
    A(ibs_section(perf))
    A("")
    A("## 4. Cortex-M4 reference cost of the same primitives (pqm4, published)\n")
    A("From `vendor/pqm4-src/benchmarks.csv`; pqm4 measured at 24 MHz to avoid flash wait "
      "states, so the ms column is cycles / 24 MHz. These are upstream numbers, not "
      "measured by us; they are the honest substitute for \"run it on the target\".\n")
    A(m4_table(rows))
    A("\n## 5. Wire sizes measured from the reference code\n")
    A(wire_table(perf))
    A("\nSignature encoding is bit-packed (w: 6 bit/coeff, z: 3 byte/coeff); measured "
      "%d B equals the analytic value %d B. The C implementation (`c/ibs.c`) sends the "
      "32-byte challenge seed instead of the expanded sparse polynomial and so needs "
      "1952 B - 12 B less, and every phase-1 message above loses the same 12 B.\n" % (
          perf["wire"]["sigma_bytes_measured"], perf["wire"]["sigma_bytes_analytic"]))
    A("Per-node stored session state: %d B (+%d B if KRA is kept in RAM as eq 5-5 says). "
      "Identity key %d B, group public key %d B.\n" % (
          perf["state"]["per_session_node_bytes"],
          perf["state"]["per_session_node_bytes_with_KRA"]
          - perf["state"]["per_session_node_bytes"],
          perf["state"]["identity_key_bytes"], perf["state"]["master_pk_bytes"]))
    kem = {r["operation"]: r["cycles_mean"] for r in perf["native"]
           if r["scheme"].startswith("ML-KEM-512")}
    kem_triple = sum(kem.get(k, 0) for k in ("keypair", "encaps", "decaps"))
    m4 = [r for r in rows["kem"] if r["scheme"] == "ml-kem-512" and r["impl"] == "m4fspeed"]
    m4_triple = (m4[0]["kg"] + m4[0]["en"] + m4[0]["de"]) if m4 else 0
    A("## 6. Per-message cost as a function of the refresh cadence\n")
    A("Hardware independent operation counts - this is what makes eq 4-20/4-21 measurable "
      "and what the thesis' \"lightweight\" claim rests on. k = 1 is Signal-style (a KEM "
      "operation per message), the design's point is large k.\n")
    A(cadence_table(perf))
    kem_triple_us = 0.0
    for r in perf["native"]:
        if r["scheme"].startswith("ML-KEM-512") and r["operation"] in ("keypair", "encaps",
                                                                       "decaps"):
            kem_triple_us += r["us_mean"]
    A("\nPlugging in section 3: one refresh is a KEM triple of %s cycles (%s µs on this "
      "laptop). Spread over k = 100 messages it adds %s cycles per message - the same order "
      "as the two KDF invocations the message ratchet already does - while a Signal-style "
      "per-message KEM (k = 1) would add the whole triple to every message, i.e. a factor of "
      "k = 100 more asymmetric work. On a Cortex-M4 at 24 MHz the same triple is %s ms at "
      "k = 100 (amortised) versus %s ms per message at k = 1, using the pqm4 m4fspeed figures.\n"
      % (
          "{:,.0f}".format(kem_triple), "{:,.0f}".format(kem_triple_us),
          "{:,.0f}".format(kem_triple / 100.0),
          ms(m4_triple / 100.0), ms(m4_triple)))
    A("## 6b. One session end to end\n")
    A(session_totals(perf))
    A("## 7. Python reference implementation latency (functional evidence only)\n")
    A(py_table(perf))
    A("\nThese are numpy/CPython numbers on a laptop and are only meaningful as ratios "
      "(sign vs verify, refresh vs message). The device-relevant figures are sections 3 and 4.\n")
    A("## 8. Deviations from the thesis text\n")
    A("1. The harness uses ML-KEM-512 in both phases; ch.5-2-7 names Kyber-512 for phase 1 "
      "and Kyber-768 for the ratchet layer. Both are benchmarked (sections 3-4) so either "
      "profile can be read off.")
    A("2. The signature is our own rank-2 Module-LWE Fiat-Shamir-with-aborts prototype "
      "following the Zhichao et al. description in ch.4-4, not a published, "
      "security-proved IBS. Finding F1 shows the specific key-derivation rule given in the "
      "thesis is broken, so this is not a silent substitution.")
    A("3. HKDF/HMAC/AEAD are instantiated as HKDF-SHA3-256, HMAC-SHA3-256 and AES-256-GCM, "
      "matching eq 4-13..4-19 and eq 4-36 with the thesis' lambda = 256 bit.")
    A("4. Key confirmation is implemented as the two-step MACB/MACA exchange of eq 4-20 "
      "plus the MACA return (eq 4-21), which the thesis describes but does not fully "
      "specify; the exact transcripts are in `Session._schedule`.")
    A("5. The prototype's rejection sampling is one-sided, and `c/bench_ibs.exe` now "
      "measures it: over %d sampled signatures the response-norm abort "
      "(`|z| <= gamma_1 - beta` = %d) fired %d times while the commitment abort fired %d "
      "times, because y is drawn from a centered binomial with eta_y = %d "
      "(`|y|_inf <= %d`, observed %d) and `c*h*s1` has norm ~25, so `|z|` peaked at %d - "
      "nowhere near the bound. Either y has to be drawn uniformly over "
      "`[-gamma_1, gamma_1]` as FIPS 204 does, or gamma_1 has to be replaced by the "
      "binomial support and the abort tightened to `eta_y + beta`; until then the "
      "hypothesis-hiding argument of the Fiat-Shamir-with-aborts proof does not transfer "
      "to this instantiation, and the sign cost is dominated by the commitment abort "
      "(%.1f attempts per signature, %.0f%% of a measured Dilithium-2 signature)." % (
          int(st.get("n", 0)), int(st.get("abort_z", 0)), int(st.get("rej_z", 0)),
          int(st.get("rej_w", 0)), int(st.get("eta_y", 0)), int(st.get("eta_y", 0)),
          int(st.get("max_y", 0)), int(st.get("max_z", 0)),
          st.get("attempts_mean", 0.0),
          100.0 * ibs_c_sign / d2sign if d2sign else 0.0))
    return "\n".join(body)


FINDINGS_TEXT = """# Findings

Five results from the harness and the symbolic models that change what chapter 5 can claim.
Each is reproducible with `python run_claims.py` plus `sh model/run_model.sh` (single-test
commands given below).

## F1 - the identity-based signature as specified leaks the PKG master key (critical)

ch.4-4 defines the master public key as `t = A*s1 + s2` and the identity key as
`usk_id = h*ID * s1`, i.e. derived from the master secret by a *homomorphic* multiplication
with a public, self-inverse-in-the-NTT-domain hash. That is not a trapdoor:

    usk_id / h*ID  =  s1        (pointwise division in the NTT domain)

h*ID is invertible in 256/256 NTT slots for the identity we tested, so any node that
received one legitimately issued key recovers `s1` bit-exactly, then re-derives signing keys
for identities the PKG never issued and produces signatures that pass `Verify`. The whole
authentication layer of phase 1 collapses: the "unforgeable" component of eq 4-5/4-6 is
forgeable by every participating node.

* Reproduce: `python -c "import lab.claims as c; print(c.c2_ibshomomorphic_identity_key_is_insecure()['observed'])"`
  and natively: `c/bench_ibs.exe`, which prints the same result before it measures anything.
* Evidence: `s1 recovered bit-exactly = True; forgery for an unissued identity verifies = True`
  (Python reference), and in C: all 512/512 NTT slots of `h` invertible, 0/512 slots differ
  from the master secret, forgery for `IIOT-GW-9999` accepted - so this is not an artifact of
  one lucky identity or of the numpy arithmetic.
* What it does **not** mean: it is not an attack on the ratchet, the key schedule or ML-KEM.
* Options for the thesis: (a) keep identity-based keys but use a GPV-style lattice
  trapdoor, i.e. sample `t` with a short trapdoor basis and preimage-sample `usk_id`, which
  is a different scheme from the one described; (b) drop to certificate-based PKI (the PKG
  signs `H(pk_id)` instead of dividing by `h`), which keeps every other equation of ch.4
  unchanged and removes the escrow of 5-2-8 at the same time; (c) keep "certificateless"
  with a partial private key that is *not* a scalar multiple of `s1`.

## F2 - the responder never checks NA freshness, so a replayed M1 opens a phantom session

M1 = (IDA, IDB, pkAe, NA, sigma_A) is bound by the signature but nothing at B tells B that
this NA was chosen now. Replaying a long-consumed M1 to a fresh responder instance makes B
accept, derive a full key set, and believe it is in an authenticated session with A - while
A is not participating at all (A refuses, because eq 4-37 erased `skAe` after its first
finalize). The AKE "matching sessions" property therefore fails.

* Reproduce: `python -c "import lab.claims as c; print(c.a5_replay_m1()['observed'])"`
* Impact: log/audit integrity (a node records an authenticated session that never happened),
  state-exhaustion on a constrained node, and a wrong foundation for the replay claim in
  5-2-3. No key is leaked.
* Fix: bind B's reply to freshness B can prove - e.g. include a B-chosen ephemeral KEM
  contribution (see F4) and/or have A sign NB into a MAC that B must see returned before it
  commits state; a timestamp/counter window on NA also closes it.

## F3 - the documented internal state contradicts the PCS claim

ch.5-3 eq 5-5 puts `KRA` *inside* the node's stored session state
(`StAL1 = {skIBS,A, pkIBS,GW, RK0, KRA}`), while ch.5-2-6 conditions post-compromise security
on "confidentiality of KRA" and ch.4-9 justifies removing the signature from the refresh
phase exactly because a state leak does not expose KRA. A memory scrape that follows eq 5-5
therefore gets KRA, and with it the attacker can *forge the asymmetric refresh itself*: it
supplies its own KEM key, authenticates MsgA with the leaked KRA, and B advances its root
key into the attacker's epoch. The attacker then reads B's next message in clear and the
honest peer A is left out of step (its next refresh aborts).

* Reproduce: `python -c "import lab.claims as c; print(c.b5_pcs_breaks_if_kra_is_stored()['observed'])"`
* Evidence: `B accepted the forged refresh (e=1); attacker opened B's post-refresh plaintext = 1`
* Complementary positive result: with only the *message* state leaked ({RK, CKs, CKr, epoch,
  TH}) KRA is **not** reachable (test b4: PASS), because KRA is derived from PRK0 and never
  re-derived from RK. The vulnerability is entirely in where the state table says to keep KRA.
* Fix: keep KRA outside the session-state domain (secure element / separate storage, never
  in the RAM the state table describes), or restore an authenticated (signed) refresh, or
  bind the refresh to a per-epoch MAC key that is ratcheted forward and never stored
  alongside RK.

## F4 - one ephemeral reveal is enough to break the session key (eCK)

In phase 1 the shared secret is a single KEM shared secret encapsulated *to A's* ephemeral
public key; B contributes only NB, which travels in the clear and enters the schedule as a
salt. So revealing A's own `skAe` - the oracle eCK explicitly grants to the test session -
gives the attacker ss0, hence PRK0, hence Ksess, RK, KRA and both chains.

* Reproduce: `python -c "import lab.claims as c; print(c.b6_ephemeral_reveal()[0]['observed'])"`
* Evidence: `attacker recovered Ksess=True, RK=True, KRA=True from the session's own ephemeral alone`
* The ratchet limits the blast radius: after one refresh the stale state opens nothing
  (second record of the same test: PASS). So this is a *stronger-forward-secrecy / eCK*
  gap, not a total break.
* Fix: make B also generate an ephemeral KEM keypair, encapsulate in both directions and set
  `ss0 = ss0_A || ss0_B` (or add a second HKDF stage). The extra cost is one keygen + one
  encaps + one decaps per session, ~%.0f%% of the current phase-1 compute.

## F5 - within-epoch forward secrecy fails for the state table as written

Found by the symbolic model, not by the harness.

eq 5-6 defines the stored message state as `{RK, CK_send, CK_recv, epoch, counters, TH}`, and
eq 4-32/4-33 define the *initial* chain key of a refreshed epoch as `HKDF(RK, "SendKeys" || e
|| TH_e)`. Both facts together mean a memory scrape that follows eq 5-6 re-derives the whole
current epoch: the attacker steps the eq 4-35 chain forward from its published starting point
and recovers the message keys of messages already consumed and erased, plus every message of
that epoch until the next refresh. `pqake_ratchet.pv` reaches `pt20` (a payload sent before
the scrape, inside the scraped epoch) while the same model does **not** reach `pt10` or
`pt30`, so this is confined to one epoch and does not weaken cross-epoch PFS (b1) or PCS (b3).

* Reproduce: `python -c "import lab.claims as c; print(c.b8_within_refreshed_epoch()['observed'])"`
* Evidence: `chain-only attacker: past 0/5 | RK attacker: past 5/5, future 3/3, other epochs 0/3`
* Why the harness missed it first: `ChainState` implemented the textbook chain adversary
  (forward-only from the leaked chain key), which is weaker than the state the model exposes.
  `RootState` is the faithful one. The epoch-0 chains escape it only because eq 4-18/4-19
  derive them from `PRK0` rather than from `RK` (test b2: RK-aware attacker gets 0/5 there).
* Fix, verified: scrape without `RK`. `pqake_ratchet_minstate.pv` is the same ratchet with
  `{CK_send, CK_recv, e, counters, TH}` exposed and `RK` withheld - all four statements come
  out true (`pt10`, `pt20`, `pt30`, `kra`). Since eq 4-31 needs `RK` to compute the next root
  key it cannot simply be deleted; it has to live outside the region the exposure oracle
  models, which is a platform-isolation requirement, not a KDF change. Note this is the same
  shape of fix as F3, and eq 5-5/5-6 are where both are written down.

## What the harness could not do here

* No proof in the computational model (QROM, ACCE game-hopping) - only a symbolic/executable
  test. ProVerif 2.05 is executed (RESULTS.md section 2b, `model/ACCE-PQAKE.md`); Tamarin is
  not, and the two statements ProVerif's fragment cannot decide are recorded as such: the
  arithmetic of F1 (section 7.1) and injective agreement through a table's negative branch
  (section 7.2).
* No Cortex-M4 cycles measured locally; section 4 of RESULTS.md quotes pqm4's published
  table instead.
* The IBS is a prototype, so its constant-time properties were not examined.
"""


def efficiency_findings(claims):
    """The overhead claims (ch.5-4..5-7) that did not reproduce, generated from the same
    records as RESULTS.md section 2 so the two cannot drift apart."""
    recs = [c for c in claims["results"] if c["test"].startswith("e")]
    if not recs:
        return ""
    bad = [c for c in recs if c["verdict"] == "FAIL"]
    good = [c for c in recs if c["verdict"] != "FAIL"]
    lines = ["## E - the efficiency claims of ch.5-4..5-7 (measured)", "",
             "The thesis derives its overhead figures analytically and never measures them. "
             "The reference implementation reproduces the *arithmetic* of every equation "
             "where the inputs are the ones the thesis assumes, and does not reproduce the "
             "figures where the inputs are the ones the design actually produces. %d of the "
             "%d quantitative claims tested here do not survive that distinction; the files "
             "are `lab/efficiency.py` and, in the tables, RESULTS.md section 2." % (
                 len(bad), len(recs)), "",
             "| claim | what the thesis states | what the implementation produces | verdict |",
             "|---|---|---|---|"]
    for c in recs:
        lines.append("| %s | %s | %s | %s |" % (
            _cell(c["claim"].split(":")[0]), _cell(c["expected"]),
            _cell(c["observed"]).replace(" | ", " / "), "**" + c["verdict"] + "**"))
    lines.append("")
    for c in bad:
        lines.append("* **%s** - %s" % (_cell(c["claim"].split(":")[0]), _cell(c["note"])))
    lines.append("")
    lines.append("What still holds, and is the part of the design worth defending: %s" %
                 "; ".join(_cell(c["claim"].split(":")[0]) for c in good))
    return "\n".join(lines) + "\n"


def findings_md(perf, claims):
    native = {r["operation"]: r["cycles_mean"] for r in perf["native"]
              if r["scheme"].startswith("ML-KEM-512")}
    extra = (native.get("keypair", 0) + native.get("encaps", 0) + native.get("decaps", 0))
    ibs = {r["operation"]: r["cycles_mean"] for r in perf["native"]
           if r["scheme"] == "IBS-K2L2"}
    phase1 = extra + ibs.get("sign", 2 * 1338173) + ibs.get("verify", 2 * 1338173)
    text = FINDINGS_TEXT.replace("~%.0f%%", "%.1f%%" % (100.0 * extra / max(phase1, 1)))
    anchor = "## What the harness could not do here"
    eff = efficiency_findings(claims)
    if anchor in text and eff:
        text = text.replace(anchor, eff + "\n" + anchor)
    else:
        text = text + "\n" + eff
    return text


def main():
    claims, perf = load()
    rows = pqm4_rows()
    open(os.path.join(HERE, "RESULTS.md"), "w", encoding="utf-8").write(
        results_md(claims, perf, rows))
    open(os.path.join(HERE, "FINDINGS.md"), "w", encoding="utf-8").write(
        findings_md(perf, claims))
    print("wrote RESULTS.md (%d bytes) and FINDINGS.md" %
          os.path.getsize(os.path.join(HERE, "RESULTS.md")))


if __name__ == "__main__":
    main()
