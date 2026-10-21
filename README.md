# P.Q.A.K.E. v1 — reference implementation and claim-test harness

Everything measured for chapter 5, section 5.8 of the thesis (the "implementation and
empirical testing of the claims" section): a runnable reference implementation of the
protocol, its dual ratchet and its identity-based signature; the attack and
state-exposure matrix; the ProVerif models; and the native measurements behind the
overhead tables.

**32 test records — 19 security claims and 13 quantitative ones — score 26 PASS,
3 DOCUMENTED-LIMITATION, 3 CONFIRMED-VULNERABLE, 0 FAIL.** The results are in
`RESULTS.md` (the matrix, timings, model verdicts) and `FINDINGS.md` (the five findings
F1–F5, each reproducible with one command).

## What the tests changed in the protocol

Two of the five findings were defects in the scheme as written, not bad statistics, and
both are repaired here rather than merely reported:

- **F2 — the responder never checked `NA` freshness.** A replayed `M1` made a fresh
  responder instance open a session with a peer that was not participating. Fixed by
  eq 4-6a: each node keeps a `Seen(IDB)` set of nonces it has already answered and
  refuses a repeat. Implemented in `Session.respond` (`lab/proto.py`), tested by `a5`,
  modelled by `model/pqake_replay_fixed.pv`.
- **F5 — a refreshed epoch's chain keys were seeded from the stored root key.** With eq
  5-6's state table, a memory scrape let an attacker walk the current epoch backwards and
  recover message keys already consumed and erased. Found by the symbolic model
  (`pqake_ratchet.pv` falsifies `pt20`), not by the harness. Fixed by eq 4-31..4-33: a
  refresh derives an intermediate `PRK_e` and seeds the chains from it. Modelled by
  `model/pqake_ratchet_prk.pv` (all four statements true), with
  `model/pqake_ratchet_minstate.pv` kept as the equivalent alternative that withholds `RK`
  instead.

Neither repair changes a wire size or an asymmetric cycle count, so the measured tables
below section 5.8's overhead rows still describe the shipped framing.

F1 (the identity-based key extraction is homomorphic, so one issued `usk_id` recovers the
PKG master secret), F3 (eq 5-5 stored `KRA` inside the session state) and F4 (one
ephemeral reveal of the test session breaks the session key, so the eCK-style claim does
not hold) are not closed by a text edit. In the thesis F3 becomes a storage requirement,
F1 and F4 narrow the claims that depend on them and are listed as future work.

## Layout

| Path | What it is |
| --- | --- |
| `lab/` | the implementation: `proto.py` (protocol), `net.py` (dual ratchet over an active Dolev-Yao channel + ACCE exposure oracle), `ibs.py` + `ring.py` (rank-2 module-lattice IBS), `claims.py` (security tests), `efficiency.py` (quantitative tests), `perf.py` (measurement driver) |
| `run_claims.py` | runs all 32 claim tests and writes `claims.json` |
| `test_ibs.py` | self-tests of the signature: completeness, soundness, escrow, master-key recovery |
| `model/` | 9 ProVerif models of the section 5.2 properties and of both repairs; `ACCE-PQAKE.md` is the oracle game, `logs/` holds the raw transcripts |
| `c/` | native C: `ibs.c` (the chapter-4 signature on the Kyber/Dilithium ring), `bench_*.c` (cycle counting), `build.sh` |
| `results/` | `perf.json` (measured cycles, wire sizes, abort rates) and `native_ops.csv` |
| `report.py` | renders `RESULTS.md` and `FINDINGS.md` from `claims.json`, `results/perf.json`, `model/logs/` and the pqm4 table |

## Running

```sh
python run_claims.py          # security + efficiency matrix -> claims.json   (Python 3.11, NumPy)
python test_ibs.py            # signature self-tests
sh model/run_model.sh         # all 9 models -> model/logs/*.log
python -m lab.perf            # re-measure native timings -> results/perf.json
python report.py              # regenerate RESULTS.md and FINDINGS.md from the artefacts above
```

`run_claims.py` and `test_ibs.py` need nothing but NumPy and reproduce the security
verdicts. `report.py` reads only files already in the repository, so `RESULTS.md` and
`FINDINGS.md` cannot drift from what the harness wrote — every table row and every
percentage in them is recomputed at build time. The ProVerif runs and the native timings
need external tools:

- **ProVerif 2.05** (Inria binary package). `model/run_model.sh` looks for
  `vendor/proverif2.05/proverif.exe`; set `PROVERIF=/path/to/proverif` to use your own.
- **Zig 0.17 as a C compiler** for `c/build.sh` (`ZIG=/path/to/zig`), plus the reference
  sources below.

## Third-party sources (not committed)

`vendor/` is ignored. Rebuild the native layer with:

```sh
git clone https://github.com/pq-crystals/kyber.git      vendor/kyber       # at 3edd5af5991927164edd4aacebfcbee00b8064e7
git clone https://github.com/pq-crystals/dilithium.git  vendor/dilithium   # at d35ba3fe5449bee3e6d43e1f296c3ca818bd36be
git clone https://github.com/mupq/pqm4.git              vendor/pqm4-src    # at e1146b1bc180c66689682f6ce63bd8f126a51ace
```

`vendor/pqm4-src/benchmarks.csv` is what `report.py` reads for the Cortex-M4 rows: no
Cortex-M4 board was available, so **every microcontroller figure in this project is
quoted from published pqm4 numbers at their stated 24 MHz clock, not measured here.**
That is flagged wherever it is used.

## Two statements ProVerif could not decide

Both are recorded as tool limits rather than as protocol results, and neither is claimed
as a proof:

- the arithmetic of F1 (NTT-domain pointwise division) is outside the symbolic model; it
  is shown by execution instead, in Python and in `c/bench_ibs.exe`.
- injective agreement through a table read's negative branch — which is exactly the shape
  of the `Seen(IDB)` cache in the F2 fix. `model/limitation_table_else.pv` is the minimal
  reproduction. For the repaired handshake, `pqake_replay_fixed.pv` proves plain
  agreement and the injective `doneB ⇒ doneA`, and leaves only the injective form of
  `acceptB ⇒ startA` undecided.

## Measured on

A single x86-64 desktop machine, cycles from a constant TSC counter with separate
calibration. Nothing here was run on embedded hardware. Windows and the local `.docx`
thesis file are not part of this repository.
