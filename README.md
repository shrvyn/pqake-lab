# P.Q.A.K.E. v1 — reference implementation and claim-test harness

Everything measured for chapter 5, section 5.8 of the thesis (the "implementation and
empirical testing of the claims" section): a runnable reference implementation of the
protocol, its dual ratchet and its identity-based signature; the attack and
state-exposure matrix; the ProVerif models; and the native measurements behind the
overhead tables.

**32 claims tested: 16 confirmed, 10 rejected, 3 confirmed vulnerabilities, 3 documented
limitations.** The five attacks that succeed are labelled F1–F5 in `FINDINGS.md`.

## Layout

| Path | What it is |
| --- | --- |
| `lab/` | the implementation: `proto.py` (protocol), `ratchet`/`net.py` (dual ratchet), `ibs.py` + `ring.py` (rank-2 module-lattice IBS), `claims.py` (security tests), `efficiency.py` (quantitative tests), `perf.py` (measurement driver) |
| `run_claims.py` | runs all 32 claim tests and writes `claims.json` |
| `test_ibs.py` | self-tests of the signature: completeness, soundness, escrow, master-key recovery |
| `model/*.pv` | 8 ProVerif models of the Section 5.2 properties; `model/ACCE-PQAKE.md` is the oracle game; `model/logs/` holds the raw transcripts |
| `c/` | native C: `ibs.c` (the chapter-4 signature on the Kyber/Dilithium ring), `bench_*.c` (cycle counting), `build.sh` |
| `results/` | `perf.json` (measured cycles, wire sizes, abort rates) and `native_ops.csv` |
| `report.py` | renders `RESULTS.md` and `FINDINGS.md` from `claims.json` + `results/perf.json` |

## Running

```sh
python run_claims.py          # security + efficiency matrix -> claims.json   (Python 3.11, NumPy)
python test_ibs.py            # signature self-tests
sh model/run_model.sh         # ProVerif 2.05 models -> model/logs/*.log
python -m lab.perf            # re-measure native timings -> results/perf.json
python report.py              # regenerate RESULTS.md and FINDINGS.md
```

The two Python commands need nothing but NumPy and reproduce the security verdicts. The
native timings and the ProVerif runs need external tools:

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
quoted from published pqm4 numbers, not measured here.** That is flagged wherever it is
used.

## Measured on

A single x86-64 desktop machine, cycles from a constant TSC counter with separate
calibration. Windows and the local `.docx` thesis file are not part of this repository.
