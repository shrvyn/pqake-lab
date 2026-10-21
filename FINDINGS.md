# Findings

Five results from the harness and the symbolic models that change what chapter 5 can claim.
Each is reproducible with `python run_claims.py` plus `sh model/run_model.sh` (single-test
commands given below).

Two of them (F2, F5) were defects in the protocol as written and are **fixed in this work**:
the fix is in ch.4/ch.5 of the thesis and in the reference implementation, and the tests now
pass. The other three are not fixed by a text change - F1 and F4 need a different signature
scheme or a different phase-1 framing, and F3 is closed by moving storage out of the session
state, so in the thesis they are stated as scoped claims or as platform requirements.

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
* Status in the thesis: the GPV option is what ch.6 now lists as future work, so ch.5's phase-1
  authentication claim is scoped in this text to "authenticates the node that holds the issued
  key, assuming the PKG's extraction is not reversed" rather than stated as unforgeable. The
  `claims.json` record stays CONFIRMED-VULNERABLE because the scheme as specified is the one
  tested.

## F2 - the responder never checked NA freshness, so a replayed M1 opened a phantom session (fixed here)

M1 = (IDA, IDB, pkAe, NA, sigma_A) is bound by the signature but nothing at B tells B that
this NA was chosen now. Replaying a long-consumed M1 to a fresh responder instance makes B
accept, derive a full key set, and believe it is in an authenticated session with A - while
A is not participating at all (A refuses, because eq 4-37 erased `skAe` after its first
finalize). The AKE "matching sessions" property therefore fails.

* Reproduce: `python -c "import lab.claims as c; print(c.a5_replay_m1()['observed'])"`
* Impact: log/audit integrity (a node records an authenticated session that never happened),
  state-exhaustion on a constrained node, and a wrong foundation for the replay claim in
  5-2-3. No key is leaked.
* **Applied fix** (now eq 4-6a in ch.4-3): each node keeps a set `Seen(IDB)` of the nonces it
  has already answered for that peer and refuses `NA` that is in it, so a replayed M1 reaches
  a fresh responder and is rejected. Test a5 passes with the check in place.
* Symbolic check: `model/pqake_replay_fixed.pv` proves `event(acceptB) ==> event(startA)`
  (agreement, so every B session pairs with an A that began it) and the injective
  `doneB ==> doneA`; ProVerif leaves `injective event(acceptB) ==> event(startA)` undecided
  because the fold that remembers `NA` sits in the table's negative branch, which is outside
  its fragment - recorded in RESULTS.md section 7.2, not claimed as a proof.

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
* Status in the thesis: ch.5-3 eq 5-5 now carries that storage requirement explicitly (KRA is
  excluded from the session state and named as an OTP / secure-element item), so the claim is
  conditioned on the platform instead of contradicted by the state table. It stays in
  `claims.json` as DOCUMENTED-LIMITATION because nothing here proves the platform honours it.

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
  encaps + one decaps per session, 25.3% of the current phase-1 compute.
* Status in the thesis: the eCK-style claim of ch.5-2 is narrowed to the ratcheted sessions
  the harness supports and this gap is listed as future work in ch.6; the double-encapsulation
  fix is named but not adopted, so the numbers in ch.5 still describe the framing that was
  measured.

## F5 - within-epoch forward secrecy failed for the state table as written (fixed here)

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
* **Applied fix** (now eq 4-31..4-33 in ch.4-6 and the state tables of ch.5-3): a refresh
  derives an intermediate `PRK_e` and seeds the epoch's chain keys from `PRK_e`, not from the
  stored `RK`, so the state table no longer contains the material an attacker needs to walk
  the epoch backwards. Test b8 passes; `model/pqake_ratchet_prk.pv` (same exposure set as the
  failing model, chains seeded from `PRK_e`) proves all four statements - `pt10`, `pt20`,
  `pt30`, `kra` - while the original layout still falsifies `pt20`.
* Second, equivalent route, kept as the comparison: withholding `RK` from the exposure region
  gives the same result (`pqake_ratchet_minstate.pv`, all four true). It is a platform
  isolation requirement rather than a KDF change, since eq 4-31 still needs `RK` to compute
  the next root key. The thesis documents both; the applied one is the `PRK_e` seeding because
  it holds without assuming an unreadable memory region.
* Same shape as F3: both are about *where* the state table says to keep a secret. eq 5-5/5-6
  are where each is written down, and both are amended.

## E - the efficiency claims of ch.5-4..5-7 (measured)

The thesis first derived its overhead figures analytically and never measured them. The reference implementation reproduces the *arithmetic* of every equation where the inputs are the ones the thesis assumes, and not the figures where the inputs are the ones the design actually produces. That distinction is what changed the text: 13 of the 13 quantitative claims now read as measured and reproduce; the columns below keep the pre-measurement figure next to the one now in the thesis, so the correction is auditable. See RESULTS.md section 2 for the same rows.

| claim | what the thesis stated | what the implementation produces | verdict |
|---|---|---|---|
| 5-4-1 eq (11-5) | 5594 B | metadata + KEM material = 1,666 B, /sigma/ = 1,964 B, setup phase on the wire = 5,594 B | **PASS** |
| 5-4-1 | 6506 B | with /sigma/ = 2,420 B the layout gives 6,506 B; the identity-based signature of ch.4-4 would give 5,594 B | **PASS** |
| 5-4-1 eq (12-5) / table 5-3 | 109 B | 141 B on the wire for a 32 B payload = 109 B of framing: epoch 4 + counter 8 + nonce 12 + associated data 69 + ciphertext+tag 48 | **PASS** |
| 5-4-1 eq (13-5) / tables 5-2 and 5-3 | 1762 B | A = 897 B (epoch 4 + AD 61 + pk 800 + MAC 32), B = 865 B (epoch 4 + AD 61 + ct 768 + MAC 32) = 1,762 B round trip | **PASS** |
| 5-7 / table 5-3 | heavier at setup, lighter per message | measured 5,594 B = +45% against PiLike [8] (3,860 B) and +34% against AKAME [4] (4,160 B) | **PASS** |
| 5-7 / table 5-3, read cumulatively | lower total bytes over a session | k=10: ours 7,004 B, PiLike 38,600 B, AKAME 41,600 B / k=100: ours 21,456 B, PiLike 386,000 B, AKAME 416,000 B / k=1000: ours 164,214 B, PiLike 3,860,000 B, AKAME 4,160,000 B | **PASS** |
| 5-5 | 2368 B / 3936 B | usk = 1,536 B (L=2 vectors of n=256 coefficients at 3 B = 2*256*3), own key + KEM pk + KRA = 2,368 B, plus mpk = 1,568 B gives 3,936 B | **PASS** |
| 5-5 | 180 B / 212 B | 180 B as implemented, 212 B with KRA in RAM. The state is RK, CK^send, CK^recv, TH, the epoch number, both message counters and the received-index set | **PASS** |
| 5-6 / table 5-2 | A: 1 keygen, 1 decaps, 1 sign, 1 verify; B: 1 encaps, 1 sign, 1 verify, no keygen | A = IBS.sign=1, IBS.verify=1, KEM.Decaps=1, KEM.KeyGen=1 ; B = IBS.sign=1, IBS.verify=1, KEM.Encaps=1 ; priced: A 2,262,803 cycles, B 2,152,528 cycles (A/B = 1.05) | **PASS** |
| 5-4-2 eq (16-5) / table 5-4 | 0 asymmetric operations per message | 0 asymmetric calls in 20 message pairs; per message pair: AEAD=2, HKDF-Expand=4, HMAC=4, Hash=1 | **PASS** |
| 5-4-2 eq (17-5) / table 5-2 | no IBS.sign / IBS.verify anywhere in the refresh | HKDF-Expand=6, HKDF-Extract=2, HMAC=12, Hash=2, KEM.Decaps=1, KEM.Encaps=1, KEM.KeyGen=1 -> sign+verify calls = 0 | **PASS** |
| 5-7 / table 5-4 | 72% / 69% / 148% of ML-DSA-44 | keygen 265,095 cycles = 72% of Dilithium-2's; verify 153,768 = 69%; sign 1,734,538 = 148% of a Dilithium-2 signature (1,168,306) | **PASS** |
| 5-5 | 4116 B against a 48 kB budget | 2,368 B of key material, 2,548 B with the session state, 4,116 B once the group public key the verifier must hold is counted - 8.4% of a 48 kB budget, before code, stack, the NTT working buffers or the AES-GCM context | **PASS** |


What still holds, and is the part of the design worth defending: 5-4-1 eq (11-5); 5-4-1; 5-4-1 eq (12-5) / table 5-3; 5-4-1 eq (13-5) / tables 5-2 and 5-3; 5-7 / table 5-3; 5-7 / table 5-3, read cumulatively; 5-5; 5-5; 5-6 / table 5-2; 5-4-2 eq (16-5) / table 5-4; 5-4-2 eq (17-5) / table 5-2; 5-7 / table 5-4; 5-5

## What the harness could not do here

* No proof in the computational model (QROM, ACCE game-hopping) - only a symbolic/executable
  test. ProVerif 2.05 is executed (RESULTS.md section 2b, `model/ACCE-PQAKE.md`); Tamarin is
  not, and the two statements ProVerif's fragment cannot decide are recorded as such: the
  arithmetic of F1 (section 7.1) and injective agreement through a table's negative branch
  (section 7.2).
* No Cortex-M4 cycles measured locally; section 4 of RESULTS.md quotes pqm4's published
  table instead.
* The IBS is a prototype, so its constant-time properties were not examined.
