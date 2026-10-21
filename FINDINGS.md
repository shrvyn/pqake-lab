# Findings

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
  encaps + one decaps per session, 25.3% of the current phase-1 compute.

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

## E - the efficiency claims of ch.5-4..5-7 (measured)

The thesis derives its overhead figures analytically and never measures them. The reference implementation reproduces the *arithmetic* of every equation where the inputs are the ones the thesis assumes, and does not reproduce the figures where the inputs are the ones the design actually produces. 8 of the 13 quantitative claims tested here do not survive that distinction; the files are `lab/efficiency.py` and, in the tables, RESULTS.md section 2.

| claim | what the thesis states | what the implementation produces | verdict |
|---|---|---|---|
| 5-4-1 eq (11-5) | 2296 B | metadata term = 1,666 B; with /sigma/ = 300 B the same layout gives 2,266 B (the thesis says 2,296 B, so the arithmetic reproduces to within the 30 B metadata constant); ch.4-4's parameters give /sigma/ = 1,964 B, so the setup phase the reference code sends is 5,594 B | **FAIL** |
| 5-4-1 | 6496 B | with /sigma/ = 2400 B the layout gives 6,466 B (0.46% from the claim, the same 30 B metadata constant as eq 11-5); with an actual ML-DSA-44 signature the reference code would send 6,506 B; with the IBS of ch.4-4 it sends 5,594 B | **PASS** |
| 5-4-1 / table 5-3 | 16 B | 141 B on the wire for a 32 B payload = 109 B of framing: epoch 4 + counter 8 + nonce 12 + associated data 69 + ciphertext+tag 48 | **FAIL** |
| 5-4-1 / tables 5-2 and 5-3 | 816 B (A) + 784 B (B) = 1600 B | A = 897 B (epoch 4 + AD 61 + pk 800 + MAC 32), B = 865 B (epoch 4 + AD 61 + ct 768 + MAC 32) = 1,762 B round trip, +81 B per leg | **FAIL** |
| 5-7 / table 5-3 | proposed below 3860 B and below 4160 B | measured 5,594 B = +45% against PiLike [8] (3,860 B) and +34% against AKAME [4] (4,160 B). The claimed ordering holds only at /sigma/ = 300 B, where the same layout gives 2,266 B | **FAIL** |
| 5-7 / table 5-3, read cumulatively | lower total bytes over a session | k=10: ours 7,004 B, PiLike 38,600 B, AKAME 41,600 B / k=100: ours 21,456 B, PiLike 386,000 B, AKAME 416,000 B / k=1000: ours 164,214 B, PiLike 3,860,000 B, AKAME 4,160,000 B | **PASS** |
| 5-5 | 1856 B | usk = 1,536 B (L=2 vectors of n=256 coefficients at 3 B = 2*256*3), so own key + KEM pk + KRA = 2,368 B; a verifier must additionally hold the group public key mpk = 1,568 B, giving 3,936 B. The 800 B term is correct: ML-KEM-512's encapsulation key measures 800 B. | **FAIL** |
| 5-5 | 104 B | 180 B as implemented, 212 B with KRA in RAM (which eq 5-5's StAL1 requires). The extra 76 B is TH (32, required by eq 4-25 and 4-36), the epoch number (4), two counters instead of one (8 + 8) and the key-confirmation material | **FAIL** |
| 5-6 / table 5-2 | A: 1 keygen, 1 decaps, 1 sign, 1 verify; B: 1 encaps, 1 sign, 1 verify, no keygen | A = IBS.sign=1, IBS.verify=1, KEM.Decaps=1, KEM.KeyGen=1 ; B = IBS.sign=1, IBS.verify=1, KEM.Encaps=1 ; priced: A 2,262,803 cycles, B 2,152,528 cycles (A/B = 1.05) | **PASS** |
| 5-4-2 eq (16-5) / table 5-4 | 0 asymmetric operations per message | 0 asymmetric calls in 20 message pairs; per message pair: AEAD=2, HKDF-Expand=4, HMAC=4, Hash=1 | **PASS** |
| 5-4-2 eq (17-5) / table 5-2 | no IBS.sign / IBS.verify anywhere in the refresh | HKDF-Expand=6, HKDF-Extract=2, HMAC=12, Hash=2, KEM.Decaps=1, KEM.Encaps=1, KEM.KeyGen=1 -> sign+verify calls = 0 | **PASS** |
| 5-7 / table 5-4 | K=L=2 should undercut K=L=4 (Dilithium-2) across the board | sign 1,734,538 cycles = 148% of a Dilithium-2 signature (1,168,306); verify 153,768 = 69% of Dilithium-2's; keygen 265,095 = 72% of Dilithium-2's | **FAIL** |
| 5-5 | node state + keys under 2048 B | 2,368 B of key material, 2,548 B with the session state, 4,116 B once the group public key the verifier must hold is counted - and that is before code, stack, the NTT working buffers or the AES-GCM context | **FAIL** |

* **5-4-1 eq (11-5)** - the equation is right and the tier is not: the 300 B signature it assumes cannot come from this scheme, whose commitment alone is 428 B (w at 6 bit/coeff = 384 B, plus the weight-39 challenge vector = 44 B) before a single response coefficient is sent. The light tier is the one table 5-3 and section 5-7 compare with the competitors, so the measured setup is 2.4x the figure the comparison uses.
* **5-4-1 / table 5-3** - the 16 B row counts the AEAD tag alone. A message that also carries what eq 4-34..4-36 requires - the epoch and message counters for key skipping, the AES-GCM nonce, and the AD that binds the message to (IDA, IDB, e, j, TH) - costs 109 B, i.e. 6.8x the table's figure. On 802.15.4 (127 B MACU) that is the difference between one frame and two.
* **5-4-1 / tables 5-2 and 5-3** - the thesis counts only the KEM material and a 16 B MAC. Eq 4-25/4-26 additionally put a 61 B epoch-binding context (AD = IDA//IDB//e//TH) and a 4 B epoch number on the wire, and the design's lambda = 256 makes the MAC 32 B not 16 B: 61 + 4 + 16 = 81 B on each leg. Table 5-3's PCS row should read 1,762 B.
* **5-7 / table 5-3** - the thesis' headline efficiency comparison inverts under measurement: as specified, the design is heavier at setup than both schemes it claims to beat. It earns the difference back on the later legs, which table 5-3 does not price - neither competitor has a ratchet ('requires re-running the key agreement' is in the same table) - so the defensible version of this claim is the cumulative one in e6.
* **5-5** - the thesis' 1024 B is neither a packed Dilithium-style secret (which is seed-sized, 32 B) nor this scheme's expanded key (1536 B): 1536 B is 512 B more, and if the group public key is counted - it must be, or nothing verifies - the long-term total is 3936 B, i.e. the section's '<2.0 kB' node budget is spent before any session state.
* **5-5** - 104 B is reachable only by dropping the transcript binding, and that binding is what makes eq 4-26's refresh authentication and the UKS resistance of 5-2-4 work. The honest figure for the protocol as specified is 180 B - still trivial for a Cortex-M4 with 48 kB of SRAM, and not compatible with the 'class 1' framing of the same section (see e13).
* **5-7 / table 5-4** - keygen and verify win exactly as the dimension argument predicts; sign loses, because beta = (tau-1)*W_H*eta+1 = 609 against Dilithium's 78 puts the per-attempt acceptance at 0.037 instead of 0.432, i.e. 26.7 rejection attempts per signature against 2.3. The cost is in the homomorphic key derivation, not the ring, so any patch that keeps usk_id = h*s1 inherits it - which includes every fix that keeps the escrow property 5-2-8 concedes.
* **5-5** - the section's own byte counts are what break its conclusion: class-1 Cortex-M parts have ~1.5-2 kB of SRAM, and this design's persistent state alone is 1.2x that before any working memory. pqm4's published figures (RESULTS.md section 4) price a single ML-DSA-44 signature on a Cortex-M4 at 3.9M-24.4M cycles depending on the optimisation level, with stack in the tens of kilobytes - so 'feasible on a class-2 M4 with 48 kB' is the supportable statement, and even there the handshake's two signatures dominate. 75% of the SRAM budget of a class-1 part is spent on keys that exist only because of the identity-based layer.

What still holds, and is the part of the design worth defending: 5-4-1; 5-7 / table 5-3, read cumulatively; 5-6 / table 5-2; 5-4-2 eq (16-5) / table 5-4; 5-4-2 eq (17-5) / table 5-2

## What the harness could not do here

* No proof in the computational model (QROM, ACCE game-hopping) - only a symbolic/executable
  test. ProVerif 2.05 is executed (RESULTS.md section 2b, `model/ACCE-PQAKE.md`); Tamarin is
  not, and the two statements ProVerif's fragment cannot decide are recorded as such: the
  arithmetic of F1 (section 7.1) and injective agreement through a table's negative branch
  (section 7.2).
* No Cortex-M4 cycles measured locally; section 4 of RESULTS.md quotes pqm4's published
  table instead.
* The IBS is a prototype, so its constant-time properties were not examined.
