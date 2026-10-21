# Security model for PQAKE-v1

This is the model the test harness (`lab/claims.py`) implements as executable games. It is
written so that chapter 5's claims become statements with named oracles, named assumptions
and a named test, instead of prose.

---

## 1. Which model, and why

| phase of the protocol | model used | why |
|---|---|---|
| phase 1, eq 4-4..4-21 (initial AKE) | **eCK** (Krawczyk-Chikara, the model ch.5 cites as [10]) with the random-oracle KDF tree read as a KDF-chain | the claims to test are authentication, session-key secrecy under *one* ephemeral or *one* long-term reveal, and UKS |
| phase 2+3, eq 4-23..4-37 (dual ratchet) | **ACCE** (Cohn-Gordon, Cremers, Schulte, Pfurtscheller, Woodings, *On the Expressive Powers of the Continuous Key Exchange Model*, IEEE S&P 2025 - already cited in ch.4-9) | only ACCE has a `StateReveal` oracle, which is what "forward secrecy" and "post-compromise security" mean; the eCK/PCK models of ch.5 cannot even state the claim |
| erase-after-use, eq 4-37 | the *erasure* variant of ACCE (Alwen, Janson, Ortner, Vornext... "Break-it, Fix-it, Fail-it, Recover-it", CCS 2022) | the claim depends on the chain state being unrecoverable, which is an assumption about the state transition, not about the primitive |

The thesis currently states its security properties in prose against a threat model
(ch.5-2). The contribution of this chapter is to re-express each of those eight claims as an
ACCE/eCK statement, then show which of them the harness could not refute and which it did.

Two independent machines answer that question:

* the **harness** (`lab/claims.py`) - executable games against a *bounded* adversary that I
  program myself, 19 claim x attack tests;
* **ProVerif 2.05** (`model/*.pv`, executed with the official Windows binary in `vendor/`) -
  a *exhaustive* Dolev-Yao adversary over the free algebra, 7 models, 41 query verdicts.

Where the two agree the claim is established twice; where they disagree, section 7 records
which of the two is over- or under-approximating the protocol.

## 2. Participants, sessions, state

A node `A` has identity `idA`, a long-term identity key pair `(usk_idA, mpk)` from the IBS of
ch.4-4, and, per session, the state of eq 5-5 / 5-6:

```
St = { RK, CK_send, CK_recv, epoch e, tx counter j, rx counter j, TH, KRA, Ksess }
```

A session is a tuple `(idA, idB, e0, j0)` plus the transcript. The adversary `X` is a
Dolev-Yao machine controlling the channel (this is `lab/net.py`: `Net.send` logs everything,
`Net.blocked` models the drop/adversary schedule, `Net.forget` models channel restoration).

## 3. Oracles

| oracle | ACCE name | harness implementation |
|---|---|---|
| `New(idA, idB)` | session initiation | `Fleet.node` + `Session.initiate` |
| `Send(inst, msg)` | delivery of an arbitrary term | `Session.respond` / `finalize` / `accept_epoch_a` / `accept_epoch_b` / `decrypt`, all of which raise `Error` on any binding violation |
| `SessionKeyTest(inst)` | test session, returns `Ksess` or a random key | comparison against `A.state["Ksess"]` (test `a1`) |
| `StateReveal(inst, level)` | the state-exposure oracle | `Session.snapshot(level)` with four levels (see below) |
| `Corrupt(id)` | long-term key disclosure | `Fleet.register` for an attacker-chosen identity (`a3`) |
| `EphemeralReveal(inst)` | eCK's `EphemeralKeyReveal` | `snapshot("ephemeral")` (`b6`) |
| `Forget` | erasure of intermediate keys | the `rx_j`/`recv_chain` advance inside `decrypt` |

What the adversary then *does* with an exposed state is itself a modelling choice, and the two
options are implemented side by side in `lab/claims.py`:

```
ChainState   step the chain forward from the leaked CK, from rx_j upwards (the textbook
             Double-Ratchet skipping-key attacker)
RootState    re-derive the epoch's initial CK from the leaked RK (eq 4-32) and run the chain
             from index 0 - the adversary the free algebra hands ProVerif
```

`try_open` reports success if either adversary opens a ciphertext, which is what makes the
harness's secrecy answers conservative rather than a function of which attacker I happened to
think of (7.3).

`StateReveal` is graded, because every one of the thesis' claims is stated with a different
implicit set of what is exposed:

```
"message_state"  = {RK, CK_send, CK_recv, e, TH, tx, rx_j}      (eq 5-6, ACCE default)
"session_state"  = message_state + Ksess
"kra"            = session_state + KRA + sk_id                  (eq 5-5 as literally written)
"ephemeral"      = + skAe / sk_KEM of the current refresh       (eCK ephemeral reveal)
```

## 4. Properties as statements

Each line is: property, the game, the assumption it needs, the harness test, and the
ProVerif query that decides the same statement exhaustively.

| # | property | harness test | ProVerif (executed) | verdict |
|---|---|---|---|---|
| 1 | Matching sessions / aliveness: acceptance at `B` implies an `A`-session with the same identities, nonce and ephemeral key | `a5` | `pqake.pv` Q2 `acceptB ==> startA` | **true** (non-injective) |
| 1b | *Uniqueness*: one acceptance at `B` per `A`-initiation (no replayed `M1`) | `a5` **refutes** | `pqake.pv` Q3 `inj-acceptB ==> inj-startA` | **false** (F2) - and `pqake_replay_fixed.pv` stays false for tool reasons, see 7.2 |
| 2 | Authentication of the peer under EUF-CMA of the IBS | `a2`, `a3`, `a7` | `pqake.pv` Q2 + Q6 `doneA ==> acceptB` | **true** - conditional on F1, which the free algebra cannot express (7.1) |
| 3 | UKS / KCI: `IDB` inside the signed term and inside `TH`, `TH` inside every derived key | `a4`, `a3` | `pqake.pv` Q2/Q6, `pqake_pkg_escrow.pv` | **true** for honest long-term keys; **false** for every query once the PKG master secret is public (D1) |
| 4 | Session-key secrecy (CK-ROR): `X` distinguishes `Ksess` without corrupting both long-term keys | `b6` | `pqake.pv` Q1 `not attacker(payloadA/payloadB)` **true**; `pqake_eck.pv` same query **false** | **refuted in the one-ephemeral case** (F4) |
| 5 | PFS backward across epochs: `StateReveal(message_state)` gives nothing about earlier-epoch payloads | `b1` (0/7 earlier-epoch messages opened) | `pqake_ratchet.pv` `not attacker(pt10[])` | **true** |
| 5b | PFS *within* the scraped epoch: the exposed state gives nothing about earlier messages of the current epoch | `b8` **refutes** (RK attacker opens 5/5 past, 3/3 future, 0/3 other epochs); `b2` passes only because epoch 0's chains come from `PRK0` | `pqake_ratchet.pv` `not attacker(pt20[])` | **false** for every refreshed epoch - mechanism, fix and corroboration in 7.3 |
| 5c | The fix for 5b: scrape `{CK_send, CK_recv, e, counters, TH}` but not `RK` | *not testable in the harness - RK is what eq 4-31 needs next* | `pqake_ratchet_minstate.pv`, all four queries | **true** |
| 6 | PCS forward: after `StateReveal`, one completed asymmetric refresh makes the stored state useless | `b3` (0/4 after 3 refreshes) | `pqake_ratchet.pv` `not attacker(pt30[])` | **true** under `message_state`; **false** under eq 5-5's literal state (`pqake_ratchet_kra.pv`: `pt30` false) |
| 7 | Refresh authenticity: `X` cannot force an honest node onto an epoch of `X`'s choosing | `b5` | `pqake_ratchet.pv` `not attacker(kra[])` **true**; `pqake_ratchet_kra.pv` **false** | **refuted under `StateReveal("kra")`** (F3) - the exposure set, not the KDF, is the bug |
| 8 | No classical assumption on the wire | `c1` | by construction (KEM + IBS + HKDF-SHA3-256 only) | held; assurance bounded by FIPS 203 and by the IBS prototype |
| 9 | IBS sID-EUF-CMA, required by 1-4 | `c2` | *not expressible* | **refuted**: `usk_id = h_ID * s1` is homomorphic in the master secret (F1) |

Phase-1 liveness note: `doneB ==> doneA` and `doneA ==> acceptB` are both true in
`pqake.pv`. The stronger `doneA ==> doneB` is *false*, and that is not a protocol break -
it is the adversary's right to withhold `MACA` after `A` has already confirmed. Liveness is
therefore asserted as "the run does not dead-lock when the channel is fair", which is what
the harness's `Net.blocked`/`Net.forget` tests measure, not as a correspondence property.

## 5. What would be needed for a proof, and what this chapter can claim

* A **computational proof** in the ACCE model (game hopping to MLWE / KEM-IND-CCA / EUF-CMA,
  in the ROM or QROM) is out of scope here: the ratchet's KDF tree would need the
  multi-stage or KDF-chain treatment of Barak-Domb / Cohn-Gordon et al., and the QROM part
  needs the measured unsampling of Fujii et al. This chapter claims **none** of that.
* What this chapter does claim: a *specification-complete* reference implementation, a
  graded exposure oracle, 19 executable games, 45 exhaustive symbolic verdicts from nine
  ProVerif model files - eight protocol models plus one tool-limitation
  reproduction - and 31 Tamarin 1.12 lemma verdicts over the two phase-1 models plus two
  restriction probes,
  that either confirm or refute each of ch.5-2's eight claims. Three
  refutations (F1, F2, F4) are construction-level and cheap to fix; one (F3) is a
  documentation inconsistency between eq 5-5 and ch.5-2-6; one more (F5, section 7.3) is a
  within-epoch PFS gap in eq 5-6 that only the symbolic model found, and whose fix the model
  also verifies (`pqake_ratchet_minstate.pv`).
* Symbolic verification **is executed**: ProVerif 2.05 (the official Inria Windows binary,
  vendored under `vendor/proverif2.05/`, no system-wide install) over all nine models, and
  Tamarin 1.12 + Maude 3.5.1 over the two phase-1 models - the properties of interest in the
  ratchet work (secrecy under a graded state reveal) are inside ProVerif's fragment, so
  ProVerif stays the primary tool, and Tamarin is used exactly where ProVerif's fragment is
  not enough, which is section 7.2. Tamarin ships Linux and macOS binaries only and this
  laptop has no JVM, WSL distribution or container runtime, so the prover runs on an
  `ubuntu-latest` GitHub Actions runner of this repository
  (`.github/workflows/tamarin.yml`), which publishes the raw transcripts back to the orphan
  branch `tamarin-logs`; they are versioned here as `model/logs/*.tamarin.log`. Nothing was
  installed locally. The harness's Dolev-Yao tests are not a substitute for either tool; they
  are the second opinion, and the places where the three disagree are the findings.

## 6. Reproduction

```sh
python run_claims.py                             # 19 claim x attack records -> claims.json
python -c "import lab.perf as P; P.measure()"    # primitives, wire sizes, cadence
sh model/run_model.sh                            # 9 ProVerif models -> model/logs/*.log
gh workflow run tamarin.yml && gh run watch       # Tamarin 1.12 on ubuntu-latest
git fetch origin tamarin-logs                     # -> model/logs/*.tamarin.log
python report.py                                 # RESULTS.md + FINDINGS.md
```

`model/run_model.sh` locates `vendor/proverif2.05/proverif.exe` itself, writes each raw
transcript to `model/logs/<name>.log`, and prints one line per query verdict, so every
number in section 4 can be re-derived without reading a log by hand. The Tamarin half cannot
run on this machine at all, so `.github/workflows/tamarin.yml` is the second half: it
installs `tamarin-prover-1.12.0-linux64-ubuntu.tar.gz` and Maude 3.5.1 into `~/.local/bin`,
proves every `model/*.spthy` file into `model/logs/<name>.tamarin.log`, and force-pushes
those transcripts to the orphan branch `tamarin-logs`, from which a plain `git fetch` reads
them back - no `gh`, no Java and no container runtime needed on the local box.

## 7. What the tool could not decide, and why

Three limits, each of which the tools were pushed until they gave a straight answer. None of
them is hidden inside a "verified" claim; 7.2 has since been closed by the Tamarin port, and
7.1 and 7.3 stay open.

### 7.1 Identity-based derivation is outside the free algebra

F1 is an *arithmetic* statement: `usk_id = h_ID * s1` lets one issued secret key divide out
the master secret. ProVerif's default no-code-generation theory treats constructors as free
terms, so `model/pqake_pkg_escrow.pv` models the consequence rather than the cause: it
publishes `uskA`/`uskB` directly (exactly what an msk-compromise yields) and then **every**
phase-1 query - secrecy of both payloads, aliveness, its injective form, and both
confirmation correspondences - flips to **false**. That is the honest reading: the tool
establishes *"if the identity keys are recoverable then the protocol has neither
authentication nor secrecy"*, and the arithmetic that makes them recoverable is established
by test `c2` in the harness, where it is a division in `Zq`.

### 7.2 ProVerif cannot use the negative branch of a table read for injectivity

`model/pqake_replay_fixed.pv` implements the F2 fix - a `seenM1(id, nonce)` cache,
`get seenM1(=A, =NA) in out(c, reject) else insert seenM1(A, NA); ...`. It kills the replay
in the real sense: `not attacker(payloadA/payloadB)`, `acceptB ==> startA`, `doneB ==> doneA`
and its injective form all report **true**. But `inj-event(acceptB) ==> inj-event(startA)`
remains **false** - and it remains false in the minimal 15-line reproduction saved as
`model/limitation_table_else.pv`, where the protocol is *obviously* injective. ProVerif's
backward search does not propagate the *failure* of a `get` as a fact available to the branch
it selects, so it cannot conclude that two acceptances must come from two distinct
initiations. The verdict is a tool limitation, not a protocol break; keeping the reproduction
file is what makes that claim checkable.

**7.2 is closed, and it was the reason for the port.** The same phase-1 process, written as
Tamarin 1.12 lemmas over trace invariants instead of ProVerif correspondences, decides it:
`model/pqake_replay_fixed.spthy` **verifies** `injective_agreement` (9 proof steps), and
`model/pqake.spthy` - identical except for one action fact and the restriction over it -
falsifies the same lemma and *verifies* `replay_trace_exists`, i.e. Tamarin writes the replay
rather than merely reporting that it cannot rule it out. Neither verdict is vacuous: the
repaired theory also verifies `handshake_possible` (an honest run reaching DoneA and DoneB on
one `Ksess`) and answers *no trace found* for `replay_trace_excluded`. So eq 4-6a does
restore injective agreement and ProVerif's **false** was an artefact of its fragment.

What the port cost, since it is a trap for anyone reusing these models: with the freshness
marker written as a *stored* fact (`SeenM1( na )` as a post-premise of B_accept) the
restriction was registered - the transcript prints it as a `safety formula` - and a lemma that
merely restates it verified, yet the solver still returned the double-accept counterexample,
which violates that very restriction. Written as an *action* fact, annotating the step that
accepts, the restriction bites and every verdict above is from that version.
`model/RestrictionProbeBefore.spthy` and `model/RestrictionProbeAfter.spthy` isolate the
behaviour in a three-rule theory: there the stored-fact form *is* enforced, with and without
`use_induction`, and declaration order makes no difference - so the gap is in the interaction
with a rule's KU-derived premises, not in the syntax.

### 7.3 Within-epoch PFS: the symbolic model found an attack the harness missed

With `message_state` exposed exactly as eq 5-6 writes it (`RK`, `CK_send`, `CK_recv`, `e`,
`TH`, counters), `pqake_ratchet.pv` reports `not attacker(pt20[])` **false**. The mechanism is
not the chain step - eq 4-35 is modelled as a one-way constructor and the adversary cannot
invert it - it is eq 4-32/4-33: the *initial* chain key of a refreshed epoch is
`HKDF(RK_e, "SendKeys" || e || TH_e)`, a function of a value the scrape publishes. So the
adversary restarts the chain at its beginning and reads that epoch both backwards, over the
keys eq 4-37 claims to have erased, and forwards, until the next refresh.
`pqake_ratchet_minstate.pv` changes only the exposure line, dropping `RK`, and then all four
statements come out **true** - which pins the cause and the fix in the same comparison.

The harness originally PASSed this case (0/5 past messages opened) because its `ChainState`
adversary implements the textbook forward-only chain attacker and never uses the `RK` in the
snapshot. `lab/claims.py` now has both: `RootState` re-derives the epoch's initial chain key
per eq 4-32, and test `b8` runs the within-epoch case *inside a refreshed epoch*, where it
reports past 5/5 and future 3/3 opened while the three epoch-0 messages stay closed. Test `b2`
keeps the epoch-0 case and stays a documented limitation, for a reason the equations give:
epoch 0's chains are the `CKA`/`CKB` leaves of `PRK0` (eq 4-18/4-19) and `RK_0 = Expand(PRK0,
"RootKey")` does not determine them, so the handshake epoch is accidentally immune and the
refreshed ones are not.

This is the strongest argument for running both machines: the harness cannot exceed the
adversary I thought of, the tool enumerates every adversary inside its fragment, and the
difference between the two verdicts *is* a finding.
