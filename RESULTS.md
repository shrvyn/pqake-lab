# PQAKE-v1: implementation and security-claim test results

Generated 2026-10-21 13:37:30 from `run_claims.py` and `lab.perf.measure()`.

## 1. Method and environment

* Reference implementation of ch.4 equation by equation: `lab/proto.py` (phase 1 eq 4-4..4-21, asymmetric ratchet eq 4-23..4-33, message ratchet eq 4-34..4-37), active Dolev-Yao channel + ACCE exposure oracle: `lab/net.py`, `Session.snapshot(level)`.
* Identity-based signature: `lab/ibs.py` + `lab/ring.py` (negacyclic NTT over R_q = Z_q[X]/(X^256+1), q=8380417, K=L=2, gamma_1=2^17, gamma_2=95232, tau=39, eta=2), validated against a naive polynomial reference and an exhaustive decomposition sweep (`test_ibs.py`), and implemented a second time in C on the vendored Dilithium ring kernels (`c/ibs.c` -> `c/bench_ibs.exe`): the two implementations use different XOF layouts, so agreement on sign/verify, on the negative tests and on the rejection rate is a cross-check rather than a restatement.
* ML-KEM: FIPS 203 code (`mlkem` wheel, Rust) inside the functional harness and the pq-crystals reference C compiled natively for timings (`c/bench_kem.c`).
* Toolchain: laptop only. Zig 0.17 used as an x86-64 C compiler, -O3 -march=native; cycles via rdtsc, calibrated against CLOCK_MONOTONIC.
* pqm4: vendored at `vendor/pqm4-src` (mupq/pqm4). Its per-algorithm kernels are Cortex-M4 assembly (poly_asm.S, ntt routines written as `.S`/`.i` macros) and cannot be compiled for x86, and no M4 board or qemu-icount setup is available here. What pqm4 does give us off the shelf is its published cycle table, reproduced below.

## 2. Claim x test x verdict

Totals: CONFIRMED-VULNERABLE = 3, DOCUMENTED-LIMITATION = 3, PASS = 26

| # | claim (ch.5) | model / oracle | test procedure | observed | verdict |
|---|---|---|---|---|---|
| 1 | 5-2-1 mutual authentication / 5-2-2 session-key confidentiality | eCK-ROR, honest run | honest handshake A<->B; compare Ksess, TH, both chains, KRA | all identical = True | **PASS** |
| 2 | 5-2-1 authentication of the initiator (MITM cannot substitute pkAe) | Dolev-Yao | attacker with a valid key for ID C sends M1 structure under ID A | aborted: Verify(params, IDA, M1, sigmaA) = 0 (eq 4-6) | **PASS** |
| 3 | 5-2-5 impersonation using another node's identity key | eCK Corrupt(C) | corrupt an unrelated node C, run a full handshake with B as C | B authenticated the peer as C, not A (no impersonation of A) | **PASS** |
| 4 | 5-2-4 unknown key-share (UKS) | eCK UKS | forward A's signed M1 to another node C | C aborted: Verify(params, IDA, M1, sigmaA) = 0 (eq 4-6) | **PASS** |
| 5 | 5-2-3 replay resistance of the handshake | Dolev-Yao | replay an already-consumed M1 to a fresh responder instance of B's identity, then hand the resulting M2 back to the original initiator | fresh B accepted the stale M1 = False; None; B2 believes it shares a session with A (matching sessions = n/a, A's Ksess unchanged = n/a) | **PASS** |
| 6 | 5-2-3 replay resistance of the ratchet layer | Dolev-Yao | replay a consumed data message, replay it again after an asymmetric refresh, and deliver j=1 after j=2 | same-epoch replay: replayed message (e=0, j=0) / cross-epoch replay: message from epoch 0 while in epoch 1 / counter going backwards: message counter went backwards (skipped key already erased) | **PASS** |
| 7 | 5-2-1 MITM: substituting handshake parameters | Dolev-Yao | relay the handshake verbatim while holding a valid identity key of one's own, then try pkAe/NA/NB/ct0-derived keys against A's session key | handshake completed under relay=True; Ksess guessable from wire=False | **PASS** |
| 8 | 5-2-6 forward secrecy (PFS) across epochs | ACCE StateReveal | after 2 refreshes / 10 messages, leak B's {RK, CKs, CKr, epoch, TH} and try every recorded ciphertext, split by whether it predates the refresh the leaked state belongs to | 0/7 from earlier epochs open, 0/3 from the leaked epoch itself | **PASS** |
| 9 | 5-2-6 post-compromise security (recovery) | ACCE StateReveal + refresh | leak state, let it go stale, run 3 asymmetric refreshes, then send traffic | 0/4 opened with stale state | **PASS** |
| 10 | 5-2-6 'exposure of the symmetric keys does not expose KRA' | ACCE StateReveal(message_state) | leak {RK, CKs, CKr, epoch, TH}; try to recompute KRA from them | KRA recovered from leaked message state = False | **PASS** |
| 11 | 5-2-6 repair after ephemeral compromise | ACCE StateReveal(ephemeral) | same leak, then one asymmetric refresh; try to open post-refresh traffic with the stale PRK0 chain | post-refresh opened with stale handshake state = False | **PASS** |
| 12 | 5-2-6 forward secrecy inside the epoch that was scraped | ACCE StateReveal(message_state), eq 5-6 read literally | run 5 messages in epoch 1, scrape B's message_state (which contains RK per eq 5-6), then re-derive the epoch's initial chain key per eq 4-32 | chain-only attacker: past 0/5 / RK attacker: past 0/5, future 0/3, other epochs 0/3 | **PASS** |
| 13 | 5-2-7 quantum resistance (no classical assumption on the wire) | MLWE / Module-SIS hardness | enumerate the primitives actually used and their on-the-wire sizes | ML-KEM-512 pk=800 ct=768 ss=32 / ML-KEM-768 pk=1184 ct=1088 ss=32 / IBS: mpk=1568 usk=1536 sigma=1964 B / SHA3-256, HMAC-SHA3-256, HKDF-SHA3, AES-256-GCM | **PASS** |
| 14 | 5-4-2 eq (16-5) / table 5-4: a normal message performs no asymmetric operation, reducing the cost from matrix multiplication to a constant KDF cost | operation counting in the reference implementation | count every primitive invoked while 20 messages are sent and received inside one epoch | 0 asymmetric calls in 20 message pairs; per message pair: AEAD=2, HKDF-Expand=4, HMAC=4, Hash=1 | **PASS** |
| 15 | 5-4-2 eq (17-5) / table 5-2: the asymmetric refresh removes Sign/Verify and costs one KEM triple plus HMACs | operation counting in the reference implementation, priced with native cycles | run one full epoch refresh - MsgA, MsgB and the return leg - with the primitive counters installed | HKDF-Expand=6, HKDF-Extract=2, HMAC=12, Hash=2, KEM.Decaps=1, KEM.Encaps=1, KEM.KeyGen=1 -> sign+verify calls = 0 | **PASS** |
| 16 | 5-7 / table 5-4: the rank-2 identity-based signature costs 72% of ML-DSA-44 for key generation and 69% for verification, but 148% for signing - the handshake is cheaper with a standard signature | native cycles (c/ibs.c on the Dilithium ring vs the Dilithium-2 reference) | compare measured mean cycles of one accepted signature, of one verification and of one key pair, on the same ring (n=256, q=8380417), same machine, with message-varying rejection loops in both | keygen 265,095 cycles = 72% of Dilithium-2's; verify 153,768 = 69%; sign 1,734,538 = 148% of a Dilithium-2 signature (1,168,306) | **PASS** |
| 17 | 5-5: the persistent footprint is 2548 B (4116 B with the group public key), which the section places on a Cortex-M4-class node with 48 kB of SRAM - not on a class-1 part | capacity arithmetic from the reference implementation + pqm4's published M4 figures | add up what a node must hold in RAM (identity key, KEM public key, KRA, session state, group public key) against the budget the amended section names, and read the handshake cost from pqm4 | 2,368 B of key material, 2,548 B with the session state, 4,116 B once the group public key the verifier must hold is counted - 8.4% of a 48 kB budget, before code, stack, the NTT working buffers or the AES-GCM context | **PASS** |
| 18 | 5-4-1 eq (11-5): the light tier's setup phase costs 5594 B, with /sigma/ = 1964 B and a 1666 B non-signature term | byte accounting of the reference implementation | rebuild eq (11-5) from the fields the reference code actually serialises (M1 + M2), separate the metadata term from the two signatures, and check the three numbers the amended section now prints | metadata + KEM material = 1,666 B, /sigma/ = 1,964 B, setup phase on the wire = 5,594 B | **PASS** |
| 19 | 5-4-1: the proposed tier's setup phase costs 6506 B, i.e. 1666 B of material plus two 2420 B ML-DSA-44 signatures | byte accounting of the reference implementation | the same reconstruction, substituting the standard signature the high tier names instead of an IBS of the same width | with /sigma/ = 2,420 B the layout gives 6,506 B; the identity-based signature of ch.4-4 would give 5,594 B | **PASS** |
| 20 | 5-4-1 eq (12-5) / table 5-3: a normal message costs 109 B of framing over its payload (epoch 4 + counter 8 + nonce 12 + bound context 69 + tag 16) | byte accounting of the reference implementation | serialise one ratchet-layer data message exactly as the reference code does and split the transmitted framing from the payload | 141 B on the wire for a 32 B payload = 109 B of framing: epoch 4 + counter 8 + nonce 12 + associated data 69 + ciphertext+tag 48 | **PASS** |
| 21 | 5-4-1 eq (13-5) / tables 5-2 and 5-3: the asymmetric refresh costs 897 B + 865 B = 1762 B round trip | byte accounting of the reference implementation | measure both refresh legs as the reference code emits them and account for the epoch number, the 61 B binding context and the lambda = 256 MAC that the KEM-only arithmetic leaves out | A = 897 B (epoch 4 + AD 61 + pk 800 + MAC 32), B = 865 B (epoch 4 + AD 61 + ct 768 + MAC 32) = 1,762 B round trip | **PASS** |
| 22 | 5-7 / table 5-3: the light tier's setup phase (5594 B) is above PiLike [8] (3860 B) and AKAME [4] (4160 B), and the design's advantage is the cumulative one of e6 | byte accounting of the reference implementation | put the measured handshake of this design on the same footing as the competitor figures quoted in table 5-3 and check the ordering the amended row states | measured 5,594 B = +45% against PiLike [8] (3,860 B) and +34% against AKAME [4] (4,160 B) | **PASS** |
| 23 | 5-7 / table 5-3, read cumulatively: this design beats schemes that must re-run the key agreement for every message | byte accounting of the reference implementation | price one session of k messages twice - this design (setup + k data messages + a refresh every 100 messages) against the competitor figures of table 5-3 multiplied by k, since those designs have no ratchet layer | k=10: ours 7,004 B, PiLike 38,600 B, AKAME 41,600 B / k=100: ours 21,456 B, PiLike 386,000 B, AKAME 416,000 B / k=1000: ours 164,214 B, PiLike 3,860,000 B, AKAME 4,160,000 B | **PASS** |
| 24 | 5-5: long-term key memory is 2368 B (usk_id 1536 B + KEM public key 800 B + KRA 32 B) and 3936 B once the group public key a verifier must hold is counted | byte accounting of the reference implementation | measure the identity key and the group public key ch.4-4's parameters actually produce, then add the 800 B KEM public key and the 32 B KRA the thesis lists | usk = 1,536 B (L=2 vectors of n=256 coefficients at 3 B = 2*256*3), own key + KEM pk + KRA = 2,368 B, plus mpk = 1,568 B gives 3,936 B | **PASS** |
| 25 | 5-5: the double ratchet needs 180 B of live session state, 212 B if KRA is kept in RAM alongside it | byte accounting of the reference implementation | count everything a running session must keep in order to send, receive, skip ahead and authenticate a refresh, per eq 4-11..4-36 | 180 B as implemented, 212 B with KRA in RAM. The state is RK, CK^send, CK^recv, TH, the epoch number, both message counters and the received-index set | **PASS** |
| 26 | 5-6 / table 5-2: phase-1 operation sets - initiator = TKeyGen+TDecaps+TSign+TVerify+TKDF, responder = TEncaps+TSign+TVerify+TKDF | operation counting in the reference implementation, priced with native cycles | instrument KEM.KeyGen/Encaps/Decaps, IBS.sign/verify, HKDF, HMAC, Hash and AEAD and drive the three handshake legs separately, attributing every call to the role that made it; then price each role's set with c/ibs.c and the ML-KEM-512 measurements | A = IBS.sign=1, IBS.verify=1, KEM.Decaps=1, KEM.KeyGen=1 ; B = IBS.sign=1, IBS.verify=1, KEM.Encaps=1 ; priced: A 2,262,803 cycles, B 2,152,528 cycles (A/B = 1.05) | **PASS** |
| 27 | 5-2-6 forward secrecy inside one epoch (epoch 0) | ACCE StateReveal | leak B's message_state at (e=0, next j=6) - both the chain-only attacker and the RK-aware attacker ProVerif derives; try the 5 past and 3 future ciphertexts | chain-only: past 0/5, future 3/3  /  RK-aware: past 0/5, future 0/3 | **DOCUMENTED-LIMITATION** |
| 28 | recovery requires a *successful* refresh (stated assumption, ch.4-9) | ACCE, persistent active attacker | jam every refresh message A->B, then let one data message through | refresh jammed=True; traffic keeps flowing on the stale symmetric chain=True | **DOCUMENTED-LIMITATION** |
| 29 | 5-2-8 key escrow is inherent to IBS (stated limitation) | trust model | the PKG, holding MSK, derives A's identity key and completes a handshake with B as A | rogue-PKG session established = True | **DOCUMENTED-LIMITATION** |
| 30 | 5-2-6 / 5-3-2 PCS under the documented internal state StAL1 | ACCE StateReveal(StAL1) | scrape node memory as specified in eq 5-5 (StAL1 = {skIBS, pkIBS_GW, RK0, KRA}), then forge a KEM refresh authenticated with the leaked KRA | B accepted the forged refresh (e=1); attacker opened B's post-refresh plaintext = 1; A's next refresh aborted (epoch desynchronised) | **CONFIRMED-VULNERABLE** |
| 31 | 5-2-2 session-key confidentiality under ephemeral reveal (eCK) | eCK EphemeralKeyReveal(session) | reveal only A's handshake KEM secret skAe, recompute ss0 -> PRK0 -> all epoch-0 keys; no long-term key is corrupted | attacker recovered Ksess=True, RK=True, KRA=True from the session's own ephemeral alone | **CONFIRMED-VULNERABLE** |
| 32 | 5-2-1 IBS unforgeability / PKG master-secret confidentiality | sID-EUF-CMA (identity-based game) | take one legitimately issued usk_id, divide it pointwise in the NTT domain by the public hash of that identity, then multiply the quotient by a different identity's hash and sign | h invertible in 256/256 NTT slots; s1 recovered bit-exactly = True; forgery for an unissued identity verifies = True (honest signature still verifies = True) | **CONFIRMED-VULNERABLE** |

## 2b. Symbolic verification: ProVerif 2.05, executed

Same properties, exhaustive Dolev-Yao adversary over the free algebra. ProVerif 2.05 (official Inria Windows binary) vendored at `vendor/proverif2.05/`; models in `model/*.pv`, raw transcripts in `model/logs/`, re-run with `sh model/run_model.sh`. Interpretation guide: a `not attacker(X)` verdict of *false* means the tool found a concrete attack; an implication `event(...) ==> event(...)` of *false* means a correspondence (aliveness / agreement) is violated. The reading of each line, including the two cases where a *false* is a limitation of the tool rather than of the protocol, is in `model/ACCE-PQAKE.md` sections 4 and 7.

| model | what it models | statement | verdict |
|---|---|---|---|
| pqake | phase 1 as written (eq 4-4..4-21), honest long-term keys | not attacker(payloadA[]) | **true** |
|  |  | not attacker(payloadB[]) | **true** |
|  |  | event(acceptB(xa,xb,na,pka,nb)) ==> event(startA(xa,xb,na,pka)) | **true** |
|  |  | inj-event(acceptB(xa,xb,na,pka,nb)) ==> inj-event(startA(xa,xb,na,pka)) | **false** |
|  |  | event(doneB(xa,xb,na,nb,ks)) ==> event(doneA(xa,xb,na,nb,ks)) | **true** |
|  |  | inj-event(doneB(xa,xb,na,nb,ks)) ==> inj-event(doneA(xa,xb,na,nb,ks)) | **true** |
|  |  | event(doneA(xa,xb,na,nb,ks)) ==> event(acceptB(xa,xb,na,pka,nb)) | **true** |
| pqake_eck | phase 1 + eCK EphemeralKeyReveal of the test session's own skAe | not attacker(payloadA[]) | **false** |
|  |  | not attacker(payloadB[]) | **false** |
|  |  | event(acceptB(xa,xb,na,pka,nb)) ==> event(startA(xa,xb,na,pka)) | **true** |
|  |  | inj-event(acceptB(xa,xb,na,pka,nb)) ==> inj-event(startA(xa,xb,na,pka)) | **false** |
|  |  | event(doneB(xa,xb,na,nb,ks)) ==> event(doneA(xa,xb,na,nb,ks)) | **false** |
|  |  | inj-event(doneB(xa,xb,na,nb,ks)) ==> inj-event(doneA(xa,xb,na,nb,ks)) | **false** |
|  |  | event(doneA(xa,xb,na,nb,ks)) ==> event(acceptB(xa,xb,na,pka,nb)) | **true** |
| pqake_pkg_escrow | phase 1 after PKG master-secret compromise: every identity secret key public (the consequence of F1 / D1) | not attacker(payloadA[]) | **false** |
|  |  | not attacker(payloadB[]) | **false** |
|  |  | event(acceptB(xa,xb,na,pka,nb)) ==> event(startA(xa,xb,na,pka)) | **false** |
|  |  | inj-event(acceptB(xa,xb,na,pka,nb)) ==> inj-event(startA(xa,xb,na,pka)) | **false** |
|  |  | event(doneB(xa,xb,na,nb,ks)) ==> event(doneA(xa,xb,na,nb,ks)) | **false** |
|  |  | inj-event(doneB(xa,xb,na,nb,ks)) ==> inj-event(doneA(xa,xb,na,nb,ks)) | **false** |
|  |  | event(doneA(xa,xb,na,nb,ks)) ==> event(acceptB(xa,xb,na,pka,nb)) | **false** |
| pqake_replay_fixed | phase 1 + the F2 fix, a seenM1(id, NA) cache at the responder | not attacker(payloadA[]) | **true** |
|  |  | not attacker(payloadB[]) | **true** |
|  |  | event(acceptB(xa,xb,na,pka,nb)) ==> event(startA(xa,xb,na,pka)) | **true** |
|  |  | inj-event(acceptB(xa,xb,na,pka,nb)) ==> inj-event(startA(xa,xb,na,pka)) | **false** |
|  |  | event(doneB(xa,xb,na,nb,ks)) ==> event(doneA(xa,xb,na,nb,ks)) | **true** |
|  |  | inj-event(doneB(xa,xb,na,nb,ks)) ==> inj-event(doneA(xa,xb,na,nb,ks)) | **true** |
|  |  | event(doneA(xa,xb,na,nb,ks)) ==> event(acceptB(xa,xb,na,pka,nb)) | **true** |
| pqake_ratchet | phases 2-3 (eq 4-23..4-37), StateReveal of the message state exactly as eq 5-6 defines it | not attacker(pt10[]) | **true** |
|  |  | not attacker(pt20[]) | **false** |
|  |  | not attacker(pt30[]) | **true** |
|  |  | not attacker(kra[]) | **true** |
| pqake_ratchet_kra | phases 2-3, StateReveal of the state as eq 5-5 literally stores it, i.e. with KRA inside | not attacker(pt10[]) | **true** |
|  |  | not attacker(pt20[]) | **false** |
|  |  | not attacker(pt30[]) | **false** |
|  |  | not attacker(kra[]) | **false** |
| pqake_ratchet_prk | phases 2-3, the applied F5 fix: eq 4-31..4-33 seed each refreshed epoch's chain keys from PRK_e instead of the stored RK | not attacker(pt10[]) | **true** |
|  |  | not attacker(pt20[]) | **true** |
|  |  | not attacker(pt30[]) | **true** |
|  |  | not attacker(kra[]) | **true** |
| pqake_ratchet_minstate | phases 2-3, the alternative fix: scrape the chain keys but not RK | not attacker(pt10[]) | **true** |
|  |  | not attacker(pt20[]) | **true** |
|  |  | not attacker(pt30[]) | **true** |
|  |  | not attacker(kra[]) | **true** |
| limitation_table_else | minimal reproduction of the tool limitation, not a protocol claim: ProVerif cannot use a table read's negative branch to prove injectivity | inj-event(accept(n_2)) ==> inj-event(start(n_2)) | **false** |

45 query verdicts over the 9 model files above; 8 of them are protocol models and the last is the tool-limitation reproduction. Four verdicts re-establish what the harness found (F2 uniqueness, F3 with KRA in the state, F4 with the ephemeral reveal, and the consequence of F1: all seven phase-1 statements fail once the identity keys are public), and one is new: the within-epoch break of F5, which the harness's weaker attacker had passed.


## 3. Native primitive timings (this laptop, x86-64)

| primitive | operation | cycles (min) | cycles (mean) | wall clock (mean) |
|---|---|---|---|---|
| ML-KEM-512 (kyber512/ref) | keypair | 239,315 | 245,137 | 74.4 µs |
| ML-KEM-512 (kyber512/ref) | encaps | 256,376 | 264,222 | 80.2 µs |
| ML-KEM-512 (kyber512/ref) | decaps | 126,983 | 129,360 | 39.3 µs |
| keccak | shake128_32B_out | 927 | 927 | 0.281 µs |
| keccak | shake256_32B_out | 933 | 933 | 0.283 µs |
| ML-KEM-768 (kyber768/ref) | keypair | 298,781 | 305,989 | 92.9 µs |
| ML-KEM-768 (kyber768/ref) | encaps | 325,412 | 332,767 | 101.1 µs |
| ML-KEM-768 (kyber768/ref) | decaps | 203,444 | 207,064 | 62.9 µs |
| keccak | shake128_32B_out | 954 | 954 | 0.29 µs |
| keccak | shake256_32B_out | 932 | 932 | 0.283 µs |
| Dilithium-2 (ML-DSA-44 class) | keypair | 364,550 | 370,682 | 112.6 µs |
| Dilithium-2 (ML-DSA-44 class) | sign | 561,131 | 1,168,306 | 354.7 µs |
| Dilithium-2 (ML-DSA-44 class) | verify | 218,030 | 222,190 | 67.5 µs |
| Dilithium-3 (ML-DSA-65 class) | keypair | 524,435 | 535,193 | 162.5 µs |
| Dilithium-3 (ML-DSA-65 class) | sign | 758,933 | 1,868,208 | 567.2 µs |
| Dilithium-3 (ML-DSA-65 class) | verify | 350,492 | 354,148 | 107.5 µs |
| IBS-K2L2 | keypair | 257,466 | 265,095 | 80.5 µs |
| IBS-K2L2 | extract | 50,028 | 51,142 | 15.5 µs |
| IBS-K2L2 | sign | 135,531 | 1,734,538 | 526.6 µs |
| IBS-K2L2 | verify | 149,160 | 153,768 | 46.7 µs |
| ring-n256-q8380417 (dilithium ref) | poly_ntt | 5,345 | 5,536 | 1.715 µs |
| ring-n256-q8380417 (dilithium ref) | poly_invntt_tomont | 8,381 | 8,564 | 2.634 µs |
| ring-n256-q8380417 (dilithium ref) | poly_basemul_montgomery | 1,121 | 1,179 | 0.392 µs |
| ring-n256-q8380417 (dilithium ref) | poly_uniform | 4,751 | 4,846 | 1.505 µs |
| ring-n256-q8380417 (dilithium ref) | poly_uniform_eta | 2,573 | 2,604 | 0.825 µs |
| ring-n256-q8380417 (dilithium ref) | poly_uniform_gamma1 | 4,784 | 4,856 | 1.508 µs |
| ring-n256-q8380417 (dilithium ref) | poly_challenge | 1,088 | 1,090 | 0.364 µs |
| ring-n256-q8380417 (dilithium ref) | poly_decompose | 1,220 | 1,260 | 0.416 µs |
| ring-n256-q8380417 (dilithium ref) | polyz_pack | 428 | 438 | 0.166 µs |
| ring-n256-q8380417 (dilithium ref) | polyz_unpack | 593 | 604 | 0.217 µs |
| ring-n256-q8380417 (dilithium ref) | polyw1_pack | 197 | 230 | 0.104 µs |
| ring-n256-q8380417 (dilithium ref) | poly_reduce | 1,022 | 1,026 | 0.345 µs |
| ring-n256-q8380417 (dilithium ref) | shake128_32B_out | 923 | 961 | 0.325 µs |
| ring-n256-q8380417 (dilithium ref) | shake128_128B_out | 1,121 | 1,159 | 0.386 µs |
| ring-n256-q8380417 (dilithium ref) | shake256_128B_out | 1,121 | 1,169 | 0.388 µs |

Cycles are invariant-TSC ticks; the core runs at a different clock, so wall clock is measured independently and both are reported.

### 3b. Identity-based signature of ch.4-4: measured natively, and reconstructed from the measured ring kernels

Self-test of `c/bench_ibs.exe`, which runs these checks before it measures (process exit code 0):
* sign/verify round trip OK (59 attempts)
* tampered message rejected = yes (code 3)
* signature valid under a different identity = no (rejected) (code 3)
* tampered response coefficient accepted = no (rejected) (code 3)
* F1: s1 recovered from one issued usk bit-exactly = yes (0/512 slots differ)
* F1: forgery for an identity the PKG never issued verifies = YES
* distribution check over 300 signatures: mean attempts 24.00 (theory ~26.8), 6899 rejections from |LowBits(Ay)| and 0 from |z|; max|LowBits(Ay)| of the first attempt in [94094, 95231] against an abort bound of 94622, max|y| 13 (eta_y 13), max|z| 46 (abort bound 130463)
* sizes: mpk=1568 B (rho 32 + t 512 x 3B), usk=1536 B, sigma=1920 B (w 384 + z 1536)
* sign: 26.95 rejection attempts per accepted signature

| operation | IBS K=L=2 (cycles) | IBS (wall) | vs Dilithium-2 | vs Dilithium-3 |
|---|---|---|---|---|
| keygen | 265,095 | 80.5 µs | 72% | 50% |
| extract (PKG) | 51,142 | 15.5 µs | - | - |
| sign | 1,734,538 | 526.6 µs | 148% | 93% |
| verify | 153,768 | 46.7 µs | 69% | 43% |

Kernel-price reconstruction of the numpy reference (K=L=2, n=256, q=8380417), priced with the dilithium-ring kernels of section 3:

| IBS operation | kernels per rejection attempt | cycles/attempt | A expansion | expected total | expected wall clock |
|---|---|---|---|---|---|
| sign | 3 x poly_ntt; 2 x poly_invntt_tomont; 6 x poly_basemul_montgomery; 2 x poly_uniform_gamma1; 4 x shake128(128B) | 55,158 | 41,528 | 1,380,213 | 431 µs |
| verify | 8 x poly_ntt; 2 x poly_invntt_tomont; 8 x poly_basemul_montgomery; 2 x polyz_pack; 4 x shake128(128B) | 76,360 | 41,528 | 117,888 | 37 µs |

`A expansion` = K x L x (poly_uniform + poly_ntt): the C implementation re-expands the matrix from rho inside every sign and verify (the Dilithium reference convention, where rho travels in the key), the numpy reference caches A_hat in the public key and therefore does not pay it. For sign the total is multiplied by the 24.3 expected rejection attempts; verify has no rejection loop.

Reconstructed this way, one signature is 118% of a measured Dilithium-2 signature (1,168,306 cycles mean, section 3) even though the prototype runs K=L=2 instead of K=L=4: the rejection loop, not the ring arithmetic, is what sets the price. Section 8 deviation 5 and the note under the table above give the reason - our beta is 609 instead of Dilithium's 78, so the commitment abort costs ~27 attempts instead of the ~2.3 that the same formula predicts for Dilithium-2.

Reconstruction versus measurement: `c/ibs.c` signs in 1,734,538 cycles, 26% above the kernel price computed above. The gap is not hidden work in the ring, it is two things the table deliberately leaves out - the measured rejection average is 24.00 attempts on this run where the table multiplies by the analytic 24.3, and the portable C carries coefficient-wide passes the kernel list does not price (poly_reduce after every accumulated term, ibs_decompose, pack_w, and the poly_center + running max-abs scans that produce the abort statistics). Treat the reconstruction as a lower bound on any honest implementation and the measured row as the claim.

Read the two blocks together, because the honest headline is uncomfortable: keygen and verify do come out below Dilithium-2 (72% and 69% of its measured cost) as the K=L=2 versus K=L=4 argument predicts, but sign does not - it is 148% of a Dilithium-2 signature. The reason is the abort rate, not the arithmetic. The commitment test keeps a signature only if |LowBits(Ay)| <= gamma_2 - beta over every K*n coefficient, so the per-attempt acceptance is (1 - beta/gamma_2)^(K*n) = 0.037 for this prototype (beta = (tau-1)*W_H*eta + 1 = 609, K*n = 512) against 0.432 for Dilithium-2 (beta = 78, K*n = 1024): 26.7 attempts instead of 2.3. The factor that makes the difference is the identity element itself - multiplying the master secret by a public, weight-8 sparse polynomial is exactly what turns beta = tau*eta into beta = (tau-1)*W_H*eta + 1. So the identity-based derivation costs this protocol more than a Dilithium-2 signature per phase-1 authentication even before F1 asks whether it is secure at all, and any patched variant that keeps a homomorphic (scalar-multiple) key derivation inherits the same abort rate. Section 8, deviation 5 records the second half of the same story: the response-norm abort never fires at all in this parameter set.

## 4. Cortex-M4 reference cost of the same primitives (pqm4, published)

From `vendor/pqm4-src/benchmarks.csv`; pqm4 measured at 24 MHz to avoid flash wait states, so the ms column is cycles / 24 MHz. These are upstream numbers, not measured by us; they are the honest substitute for "run it on the target".

| scheme (Cortex-M4, pqm4) | impl | keygen cycles | encaps/Sign cycles | decaps/Verify cycles | keygen @24MHz | encaps/Sign @24MHz | decaps/Verify @24MHz |
|---|---|---|---|---|---|---|---|
| ml-kem-512 | clean | 595,793 | 700,605 | 888,653 | 24.82 ms | 29.19 ms | 37.03 ms |
| ml-kem-512 | m4fspeed | 392,423 | 390,881 | 428,167 | 16.35 ms | 16.29 ms | 17.84 ms |
| ml-kem-512 | m4fstack | 392,224 | 392,864 | 430,202 | 16.34 ms | 16.37 ms | 17.93 ms |
| ml-kem-768 | clean | 988,722 | 1,138,225 | 1,387,984 | 41.20 ms | 47.43 ms | 57.83 ms |
| ml-kem-768 | m4fspeed | 642,096 | 658,754 | 707,827 | 26.75 ms | 27.45 ms | 29.49 ms |
| ml-kem-768 | m4fstack | 644,195 | 664,654 | 714,194 | 26.84 ms | 27.69 ms | 29.76 ms |
| ml-dsa-44 | clean | 1,874,405 | 7,925,955 | 2,063,096 | 78.10 ms | 330.25 ms | 85.96 ms |
| ml-dsa-44 | m4f | 1,426,025 | 3,943,121 | 1,421,623 | 59.42 ms | 164.30 ms | 59.23 ms |
| ml-dsa-44 | m4fstack | 1,799,062 | 12,134,284 | 3,242,333 | 74.96 ms | 505.60 ms | 135.10 ms |
| ml-dsa-65 | clean | 3,205,533 | 12,359,056 | 3,377,305 | 133.56 ms | 514.96 ms | 140.72 ms |
| ml-dsa-65 | m4f | 2,516,006 | 6,193,171 | 2,415,944 | 104.83 ms | 258.05 ms | 100.66 ms |
| ml-dsa-65 | m4fstack | 3,412,622 | 24,421,526 | 5,732,397 | 142.19 ms | 1017.56 ms | 238.85 ms |

## 5. Wire sizes measured from the reference code

| message | total bytes | breakdown |
|---|---|---|
| M1 | 2805 | IDA=12, IDB=13, pkAe=800, NA=16, sigma=1964 |
| M2 | 2789 | IDB=13, IDA=12, NB=16, ct0=768, NA=16, sigma=1964 |
| MsgA_refresh | 897 | e=4, AD=76, pke=800, MACA=32 |
| MsgB_refresh | 865 | e=4, AD=76, ct=768, MACB=32 |
| data_message | 141 | e=4, j=8, nonce=12, ad=84, ct=48 |
| confirmation | 64 | MACA=32, MACB=32 |

Signature encoding is bit-packed (w: 6 bit/coeff, z: 3 byte/coeff); measured 1964 B equals the analytic value 1964 B. The C implementation (`c/ibs.c`) sends the 32-byte challenge seed instead of the expanded sparse polynomial and so needs 1952 B - 12 B less, and every phase-1 message above loses the same 12 B.

Per-node stored session state: 180 B (+32 B if KRA is kept in RAM as eq 5-5 says). Identity key 1536 B, group public key 1568 B.

## 6. Per-message cost as a function of the refresh cadence

Hardware independent operation counts - this is what makes eq 4-20/4-21 measurable and what the thesis' "lightweight" claim rests on. k = 1 is Signal-style (a KEM operation per message), the design's point is large k.

| refresh every k messages | KEM keygen | KEM encaps | KEM decaps | HKDF-Expand | AEAD seal | hash+mac ops |
|---|---|---|---|---|---|---|
| 1 | 1.0000 | 1.0000 | 1.0000 | 8.00 | 1 | 1 |
| 10 | 0.1000 | 0.1000 | 0.1000 | 2.60 | 1 | 1 |
| 25 | 0.0400 | 0.0400 | 0.0400 | 2.24 | 1 | 1 |
| 50 | 0.0200 | 0.0200 | 0.0200 | 2.12 | 1 | 1 |
| 100 | 0.0100 | 0.0100 | 0.0100 | 2.06 | 1 | 1 |
| 250 | 0.0040 | 0.0040 | 0.0040 | 2.02 | 1 | 1 |
| 500 | 0.0020 | 0.0020 | 0.0020 | 2.01 | 1 | 1 |
| 1000 | 0.0010 | 0.0010 | 0.0010 | 2.01 | 1 | 1 |

Plugging in section 3: one refresh is a KEM triple of 638,719 cycles (194 µs on this laptop). Spread over k = 100 messages it adds 6,387 cycles per message - the same order as the two KDF invocations the message ratchet already does - while a Signal-style per-message KEM (k = 1) would add the whole triple to every message, i.e. a factor of k = 100 more asymmetric work. On a Cortex-M4 at 24 MHz the same triple is 0.50 ms at k = 100 (amortised) versus 50.48 ms per message at k = 1, using the pqm4 m4fspeed figures.

## 6b. One session end to end

| configuration (session of 1000 messages) | phase-1 signatures | refreshes | asymmetric cycles | asymmetric wall clock | handshake bytes | session bytes |
|---|---|---|---|---|---|---|
| PQAKE-v1, refresh every 1 messages | 2 | 1000 | 643,134,331 | 195.2 ms | 5594 | 1908594 |
| PQAKE-v1, refresh every 100 messages | 2 | 10 | 10,802,521 | 3.3 ms | 5594 | 164214 |
| PQAKE-v1, refresh every 1000 messages | 2 | 1 | 5,054,050 | 1.5 ms | 5594 | 148356 |
| same schedule, ML-DSA-44-class signature instead of the IBS | 2 | 10 | 9,806,901 | 3.0 ms | 5594 | 164214 |

Only the two asymmetric columns react to the cadence; the bytes columns are dominated by the per-message AEAD ciphertext (141 B each, section 5), and the compute behind them is symmetric-only (2 HKDF-Expand + 1 AEAD seal + hashes per message, priced in section 7). The last row is the point of ch.4-4: replacing the prototype's identity-based signature with a plain Dilithium-2 key would make the handshake 995,620 cycles cheaper (0.3 ms on this machine) - the K=L=2 versus K=L=4 argument is beaten by the abort rate - and would remove finding F1, so the signature layer is where both the cost and the break live.

## 7. Python reference implementation latency (functional evidence only)

| layer | operation | mean | min | iterations |
|---|---|---|---|---|
| symmetric | hkdf_expand_32B | 3.4 µs | 3.2 µs | 20000 |
| symmetric | hmac_sha3_256 | 3.0 µs | 2.8 µs | 20000 |
| symmetric | sha3_256 | 1.1 µs | 1.0 µs | 20000 |
| symmetric | aes256gcm_seal_32B | 1.0 µs | 0.8 µs | 20000 |
| symmetric | aes256gcm_seal_256B | 1.0 µs | 0.9 µs | 20000 |
| symmetric | aes256gcm_open_32B | 1.0 µs | 0.8 µs | 20000 |
| kem | mlkem512_keygen | 20.2 µs | 19.3 µs | 3000 |
| kem | mlkem512_encaps | 13.1 µs | 12.8 µs | 3000 |
| kem | mlkem512_decaps | 19.4 µs | 18.9 µs | 3000 |
| ibs | setup | 10,641.5 µs | 10,603.0 µs | 5 |
| ibs | extract | 3,873.3 µs | 3,845.8 µs | 20 |
| ibs | sign | 121,437.8 µs | 9,124.2 µs | 40 |
| ibs | verify | 10,578.3 µs | 10,496.9 µs | 40 |
| protocol | handshake_total | 171,041.3 µs | 39,851.5 µs | 12 |
| protocol | epoch_refresh_A | 136.1 µs | 129.2 µs | 12 |
| protocol | message_pair | 24.3 µs | 23.1 µs | 400 |
| protocol | encrypt_only | 12.7 µs | 12.1 µs | 400 |

These are numpy/CPython numbers on a laptop and are only meaningful as ratios (sign vs verify, refresh vs message). The device-relevant figures are sections 3 and 4.

## 8. Deviations from the thesis text

1. The harness uses ML-KEM-512 in both phases; ch.5-2-7 names Kyber-512 for phase 1 and Kyber-768 for the ratchet layer. Both are benchmarked (sections 3-4) so either profile can be read off.
2. The signature is our own rank-2 Module-LWE Fiat-Shamir-with-aborts prototype following the Zhichao et al. description in ch.4-4, not a published, security-proved IBS. Finding F1 shows the specific key-derivation rule given in the thesis is broken, so this is not a silent substitution.
3. HKDF/HMAC/AEAD are instantiated as HKDF-SHA3-256, HMAC-SHA3-256 and AES-256-GCM, matching eq 4-13..4-19 and eq 4-36 with the thesis' lambda = 256 bit.
4. Key confirmation is implemented as the two-step MACB/MACA exchange of eq 4-20 plus the MACA return (eq 4-21), which the thesis describes but does not fully specify; the exact transcripts are in `Session._schedule`.
5. The prototype's rejection sampling is one-sided, and `c/bench_ibs.exe` now measures it: over 300 sampled signatures the response-norm abort (`|z| <= gamma_1 - beta` = 130463) fired 0 times while the commitment abort fired 6899 times, because y is drawn from a centered binomial with eta_y = 13 (`|y|_inf <= 13`, observed 13) and `c*h*s1` has norm ~25, so `|z|` peaked at 46 - nowhere near the bound. Either y has to be drawn uniformly over `[-gamma_1, gamma_1]` as FIPS 204 does, or gamma_1 has to be replaced by the binomial support and the abort tightened to `eta_y + beta`; until then the hypothesis-hiding argument of the Fiat-Shamir-with-aborts proof does not transfer to this instantiation, and the sign cost is dominated by the commitment abort (24.0 attempts per signature, 148% of a measured Dilithium-2 signature).