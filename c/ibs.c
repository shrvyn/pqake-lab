/* Native implementation + benchmark of the identity-based signature of ch.4-4
 * (thesis8.docx), i.e. the rank-2 Module-LWE Fiat-Shamir-with-aborts prototype that
 * lab/ibs.py implements in numpy.  Same parameters (K=L=2, n=256, q=8380417,
 * gamma1=2^17, gamma2=(q-1)/88=95232, tau=39, weight(h)=8, eta=2, eta_y=13), same
 * algorithms Setup/Extract/Sign/Verify, built on the vendored Dilithium ring kernels
 * (poly.c/ntt.c/reduce.c/rounding.c) - the same n, the same q, the same negacyclic NTT,
 * so the cycle counts are directly comparable to the Dilithium rows of RESULTS.md.
 *
 * The XOF layout differs from the numpy reference (poly_uniform takes one 16-bit nonce
 * per polynomial, the identity element h is sampled by the same scan-with-distinct-
 * positions rule but from a shake256 stream), so this is not bit-identical to lab/ibs.py;
 * it is the same scheme, and correctness is established here by sign/verify round trips,
 * by a negative test on a tampered message, and by the F1 reproduction at the bottom of
 * main(): dividing an issued usk_id by the public h recovers s1, which then signs for an
 * identity the PKG never issued.
 *
 * Sampling loops are portable C (popcount-based binomial), not the Cortex-M4 assembly of
 * pqm4's m4fspeed rows; read the numbers as "this scheme, compiled for x86-64".
 */
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "params.h"      /* N, Q, TAU, GAMMA1, GAMMA2, SEEDBYTES, CTILDEBYTES */
#include "poly.h"
#include "fips202.h"
#include "randombytes.h"

#define IBK 2                       /* rows of A / number of t polynomials */
#define IBL 2                       /* cols of A / number of s1 polynomials */
#define ALPHA (2 * GAMMA2)
#define NDIGITS ((Q - 1) / ALPHA)   /* 44 */
#define WH 8                        /* Hamming weight of the identity element h */
#define ETA 2                       /* binomial order of s1, s2 */
#define ETA_Y 13                    /* binomial order of y */
#define IBETA ((TAU - 1) * WH * ETA + 1)
#define ABORT_Z (GAMMA1 - IBETA)
#define ABORT_W (GAMMA2 - IBETA - 1)
#define WBYTES (IBK * N * 6 / 8)    /* high bits, 6 bits per coefficient */
#define MSGLEN 57                   /* |M1| = IDA||IDB||pkAe||NA */
#define IDLEN 12

static long g_attempts;             /* rejection loop iterations of the last sign */
static int32_t g_diag_maxlo;        /* max |LowBits(A y)| of the first attempt, for checks */
static int32_t g_diag_maxy;
static int32_t g_diag_maxz;
static long g_rej_w;                /* attempts rejected by |LowBits(Ay)| */
static long g_rej_z;                /* attempts rejected by |z| */

/* ------------------------------------------------------------------ samplers */

static void shake_to(uint8_t *out, size_t n, const uint8_t *in, size_t inlen) {
  shake256(out, n, in, inlen);
}

/* centered binomial: 2*eta bits per coefficient, |a| <= eta.
 * A 64-bit window plus popcount replaces dilithium's per-eta templates, which only go
 * to eta = 6 and would not cover ETA_Y = 13. */
static void poly_cbd(poly *r, const uint8_t *buf, unsigned eta) {
  unsigned i, j;
  uint64_t acc = 0;
  int bits = 0;
  uint64_t mask = ((uint64_t)1 << eta) - 1;
  size_t pos = 0;
  for (i = 0; i < N; i++) {
    while (bits < 2 * (int)eta) {
      uint64_t byte = buf[pos++];
      acc |= byte << bits;
      bits += 8;
    }
    {
      unsigned a = 0, b = 0;
      for (j = 0; j < eta; j++) {
        a += (unsigned)(acc & 1);
        acc >>= 1;
      }
      for (j = 0; j < eta; j++) {
        b += (unsigned)(acc & 1);
        acc >>= 1;
      }
      r->coeffs[i] = (int32_t)a - (int32_t)b;
      (void)mask;
    }
    bits -= 2 * (int)eta;
  }
}

/* dilithium's poly_reduce is reduce32: a symmetric representative in
 * [-6283008, 6283008], which is what the NTT kernels want but is NOT the standard
 * representative [0, Q) that the decomposition and the bit packers need.  freeze =
 * reduce + caddq, exactly the reduce/invntt/caddq sequence of dilithium's own sign.c. */
static void poly_freeze(poly *a) {
  poly_reduce(a);
  poly_caddq(a);
}

/* Plain NTT of the negacyclic product a*b, given the plain NTTs of a and b.
 * pointwise_montgomery contributes a factor 2^-32 and invntt_tomont multiplies by 2^32,
 * so the pair is an exact product in the normal domain; transforming back afterwards is
 * what keeps every NTT-domain polynomial in our equations on ONE consistent scaling. */
static void ntt_mul(poly *r, const poly *a_hat, const poly *b_hat) {
  poly_pointwise_montgomery(r, a_hat, b_hat);
  poly_invntt_tomont(r);
  poly_freeze(r);
  poly_ntt(r);
}

/* sparse weight-WH element with signs, from a shake stream (the rule of ibs.expand_h) */
static void poly_sparse(poly *h, const uint8_t *stream, unsigned weight) {
  unsigned i, have = 0;
  int8_t pos[64];
  for (i = 0; i < N; i++) h->coeffs[i] = 0;
  for (i = 0; i < 256 && have < weight; i++) {
    unsigned p = stream[i], k;
    if (p >= N) continue;
    for (k = 0; k < have; k++) if (pos[k] == (int8_t)p) break;
    if (k < have) continue;
    pos[have++] = (int8_t)p;
  }
  for (i = 0; i < have; i++) {
    unsigned bit = (stream[weight + i / 8] >> (i % 8)) & 1;
    h->coeffs[pos[i]] = bit ? 1 : Q - 1;
  }
}

static void poly_center(poly *a) {
  unsigned i;
  for (i = 0; i < N; i++) {
    int32_t t = a->coeffs[i] % Q;
    t += (Q - 1) / 2;
    t %= Q;
    t -= (Q - 1) / 2;
    a->coeffs[i] = t;
  }
}

static int poly_maxabs_centered(const poly *a, int32_t *out) {
  unsigned i;
  int32_t m = 0;
  for (i = 0; i < N; i++) {
    int32_t t = a->coeffs[i] % Q;
    t += (Q - 1) / 2;
    t %= Q;
    t -= (Q - 1) / 2;
    if (t < 0) t = -t;
    if (t > m) m = t;
  }
  *out = m;
  return m;
}

/* The thesis' decomposition, eq 4-34/4-35 style: v = m*ALPHA + s with m in [0,43] and
 * s in [-GAMMA2+1, GAMMA2].  dilithium's poly_decompose cannot be used: it folds the 44th
 * digit back onto 0 without re-centering, which puts about 2.3% of the coefficients at
 * |s| ~ 194000 and makes the |LowBits| <= GAMMA2 - BETA abort reject essentially every
 * attempt (observed: 27M rejections, no signature).  This version matches lab/ibs.py. */
static void ibs_decompose(poly *a1, poly *a0, const poly *a) {
  unsigned i;
  for (i = 0; i < N; i++) {
    int32_t r = a->coeffs[i];              /* standard representative, [0, Q) */
    int32_t m = (r + GAMMA2 - 1) / ALPHA;
    int32_t s;
    if (m >= NDIGITS) m = 0;
    s = r - m * ALPHA;
    if (s > GAMMA2) s -= Q;                /* the wrapped top digit */
    a1->coeffs[i] = m;
    a0->coeffs[i] = s;
  }
}

static void pack_w(uint8_t *r, const poly *hi, unsigned npoly) {
  unsigned i, b;
  uint32_t buf = 0;
  int cnt = 0;
  size_t out = 0;
  for (i = 0; i < npoly * N; i++) {
    unsigned idx = i / N, c = i % N;
    buf |= (uint32_t)(hi[idx].coeffs[c] & 63) << cnt;
    cnt += 6;
    while (cnt >= 8) {
      r[out++] = (uint8_t)(buf & 0xff);
      buf >>= 8;
      cnt -= 8;
    }
  }
  if (cnt) r[out++] = (uint8_t)(buf & 0xff);
  (void)b;
}

/* ------------------------------------------------------------------ key material */

typedef struct {
  uint8_t rho[SEEDBYTES];
  poly t[IBK];                 /* normal domain */
} ibs_pk;

typedef struct {
  uint8_t rho[SEEDBYTES];
  poly s1[IBL];                /* normal domain */
  poly s2[IBK];
} ibs_msk;

/* usk_id = h * s1, kept in the plain NTT domain (no Montgomery factor), exactly as the
 * sign loop needs it: one pointwise_montgomery with c_hat plus one invntt_tomont is then
 * the exact negacyclic product c*h*s1. */
typedef poly ibs_usk[IBL];

static void gen_matrix(poly A[IBK][IBL], const uint8_t rho[SEEDBYTES]) {
  unsigned i, j;
  for (i = 0; i < IBK; i++)
    for (j = 0; j < IBL; j++) {
      poly_uniform(&A[i][j], rho, (uint16_t)(i * IBL + j));
      poly_ntt(&A[i][j]);
    }
}

static void ibs_setup(ibs_pk *pk, ibs_msk *msk) {
  poly A[IBK][IBL];
  poly s1_hat[IBL], acc, tmp;
  uint8_t seed[SEEDBYTES], ext[SEEDBYTES + 2];
  unsigned i, j;
  const size_t PER = (size_t)N * 2 * ETA / 8 + 1;
  uint8_t *buf = malloc((IBL + IBK) * PER);

  randombytes(seed, SEEDBYTES);
  memcpy(pk->rho, seed, SEEDBYTES);
  memcpy(msk->rho, seed, SEEDBYTES);

  /* one shake stream holds s1 then s2, as in the reference */
  memcpy(ext, seed, SEEDBYTES);
  ext[SEEDBYTES] = 0xA1;
  ext[SEEDBYTES + 1] = 0x49;
  shake256(buf, (IBL + IBK) * PER, ext, sizeof(ext));
  {
    uint8_t *p = buf;
    for (j = 0; j < IBL; j++) {
      poly_cbd(&msk->s1[j], p, ETA);
      p += PER;
    }
    for (i = 0; i < IBK; i++) {
      poly_cbd(&msk->s2[i], p, ETA);
      p += PER;
    }
  }
  free(buf);

  gen_matrix(A, pk->rho);
  for (j = 0; j < IBL; j++) {
    s1_hat[j] = msk->s1[j];
    poly_ntt(&s1_hat[j]);
  }
  for (i = 0; i < IBK; i++) {
    poly_pointwise_montgomery(&acc, &A[i][0], &s1_hat[0]);
    for (j = 1; j < IBL; j++) {
      poly_pointwise_montgomery(&tmp, &A[i][j], &s1_hat[j]);
      poly_add(&acc, &acc, &tmp);
      poly_reduce(&acc);          /* keep |coef| < Q for the inverse NTT */
    }
    poly_invntt_tomont(&acc);
    poly_freeze(&acc);
    poly_add(&pk->t[i], &acc, &msk->s2[i]);
    poly_freeze(&pk->t[i]);
  }
}

static void identity_hash(poly *h, const uint8_t *id, size_t idlen) {
  uint8_t stream[64], in[5 + 32];
  size_t ll = idlen < 32 ? idlen : 32;
  memcpy(in, "IBS-H", 5);
  memset(in + 5, 0, 32);
  memcpy(in + 5, id, ll);
  shake_to(stream, sizeof(stream), in, 5 + ll);
  poly_sparse(h, stream, WH);
}

static void ibs_extract(ibs_usk usk, const ibs_msk *msk, const uint8_t *id, size_t idlen) {
  poly h, h_hat, s1_hat;
  unsigned j;
  identity_hash(&h, id, idlen);
  h_hat = h;
  poly_ntt(&h_hat);
  for (j = 0; j < IBL; j++) {
    s1_hat = msk->s1[j];
    poly_ntt(&s1_hat);
    ntt_mul(&usk[j], &h_hat, &s1_hat);
  }
}

/* the public h of an identity, needed by the verifier and by the F1 demonstration */
static void ntt_of_identity(poly *h_hat, const uint8_t *id, size_t idlen) {
  poly h;
  identity_hash(&h, id, idlen);
  *h_hat = h;
  poly_ntt(h_hat);
}

/* ------------------------------------------------------------------ sign / verify */

typedef struct {
  uint8_t w[WBYTES];
  uint8_t cseed[CTILDEBYTES];
  poly z[IBL];                 /* centered coefficients */
} ibs_signature;

static void challenge_seed(uint8_t out[CTILDEBYTES], const uint8_t *id, size_t idlen,
                           const uint8_t *mu, size_t mlen, const uint8_t *w) {
  uint8_t in[8 + IDLEN + MSGLEN + WBYTES];
  size_t n = 0;
  memcpy(in + n, "IBS-C", 5);
  n += 5;
  memset(in + n, 0, 3);
  n += 3;
  memcpy(in + n, id, idlen < IDLEN ? idlen : IDLEN);
  n += IDLEN;
  memcpy(in + n, mu, mlen < MSGLEN ? mlen : MSGLEN);
  n += MSGLEN;
  memcpy(in + n, w, WBYTES);
  n += WBYTES;
  shake256(out, CTILDEBYTES, in, n);
}

static int ibs_sign(ibs_signature *sig, const ibs_pk *pk, const ibs_usk usk,
                    const uint8_t *id, size_t idlen, const uint8_t *mu, size_t mlen,
                    unsigned max_attempts) {
  poly A[IBK][IBL];
  poly y[IBL], y_hat[IBL], Ay[IBK], hi[IBK], lo[IBK], c, c_hat, tmp, tmp2;
  uint8_t seed[SEEDBYTES + IDLEN + MSGLEN + 5];
  unsigned attempt, i, j;
  int32_t m;
  const size_t YBYTES = (size_t)N * 2 * ETA_Y / 8 + 1;
  uint8_t *ybuf = malloc(YBYTES);

  gen_matrix(A, pk->rho);
  /* y is re-derived per (identity, message, attempt, coordinate): binding it to the
     message is what lab/ibs.py's _sample_y does, and two bytes of attempt keep a long
     rejection loop from ever re-sampling the same y. */
  memset(seed, 0, sizeof(seed));
  memcpy(seed, pk->rho, SEEDBYTES);
  memcpy(seed + SEEDBYTES, id, idlen < IDLEN ? idlen : IDLEN);
  memcpy(seed + SEEDBYTES + IDLEN, mu, mlen < MSGLEN ? mlen : MSGLEN);
  seed[SEEDBYTES + IDLEN + MSGLEN] = 0xB3;

  for (attempt = 0; attempt < max_attempts; attempt++) {
    g_attempts = (long)attempt + 1;
    for (j = 0; j < IBL; j++) {
      seed[SEEDBYTES + IDLEN + MSGLEN + 1] = (uint8_t)j;
      seed[SEEDBYTES + IDLEN + MSGLEN + 2] = (uint8_t)(attempt & 0xff);
      seed[SEEDBYTES + IDLEN + MSGLEN + 3] = (uint8_t)(attempt >> 8);
      shake256(ybuf, YBYTES, seed, sizeof(seed));
      poly_cbd(&y[j], ybuf, ETA_Y);
      y_hat[j] = y[j];
      poly_ntt(&y_hat[j]);
    }
    for (i = 0; i < IBK; i++) {
      poly_pointwise_montgomery(&tmp, &A[i][0], &y_hat[0]);
      for (j = 1; j < IBL; j++) {
        poly_pointwise_montgomery(&tmp2, &A[i][j], &y_hat[j]);
        poly_add(&tmp, &tmp, &tmp2);
        poly_reduce(&tmp);
      }
      poly_invntt_tomont(&tmp);
      poly_freeze(&tmp);          /* LowBits needs the [0, Q) representative */
      Ay[i] = tmp;
    }
    for (i = 0; i < IBK; i++) ibs_decompose(&hi[i], &lo[i], &Ay[i]);
    /* abort if any low part is too close to a digit boundary for |c*h*s2| */
    {
      int reject = 0;
      int32_t mx = 0;
      for (j = 0; j < IBL; j++) {
        poly yy = y[j];
        poly_maxabs_centered(&yy, &m);
        if (m > g_diag_maxy) g_diag_maxy = m;
      }
      for (i = 0; i < IBK; i++) {
        poly_maxabs_centered(&lo[i], &m);
        if (m > mx) mx = m;
        if (m > ABORT_W) reject = 1;
      }
      if (attempt == 0 && mx > g_diag_maxlo) g_diag_maxlo = mx;
      if (reject) { g_rej_w++; continue; }
    }
    pack_w(sig->w, hi, IBK);
    challenge_seed(sig->cseed, id, idlen, mu, mlen, sig->w);
    poly_challenge(&c, sig->cseed);
    c_hat = c;
    poly_ntt(&c_hat);
    for (j = 0; j < IBL; j++) {
      poly_pointwise_montgomery(&tmp, &c_hat, &usk[j]);
      poly_invntt_tomont(&tmp);
      poly_add(&sig->z[j], &y[j], &tmp);
      poly_freeze(&sig->z[j]);
      poly_center(&sig->z[j]);     /* now a genuine centered representative */
      poly_maxabs_centered(&sig->z[j], &m);
      if (m > g_diag_maxz) g_diag_maxz = m;
      if (m > ABORT_Z) { g_rej_z++; break; }
    }
    if (j < IBL) continue;
    return 0;
  }
  free(ybuf);
  return -1;
}

static int ibs_verify(const ibs_signature *sig, const ibs_pk *pk,
                      const uint8_t *id, size_t idlen, const uint8_t *mu, size_t mlen) {
  poly A[IBK][IBL];
  poly hi[IBK], low, t_hat[IBK], z_hat[IBL], c, c_hat, h_hat, az, ct, ht, tmp;
  uint8_t w2[WBYTES];
  uint8_t cseed2[CTILDEBYTES];
  unsigned i, j, k;
  int32_t m;

  for (j = 0; j < IBL; j++) {
    poly z = sig->z[j];
    for (k = 0; k < N; k++) if (z.coeffs[k] < 0) z.coeffs[k] += Q;
    poly_maxabs_centered(&z, &m);
    if (m > ABORT_Z) return 1;
    z_hat[j] = z;
    poly_ntt(&z_hat[j]);
  }
  challenge_seed(cseed2, id, idlen, mu, mlen, sig->w);
  poly_challenge(&c, cseed2);
  c_hat = c;
  poly_ntt(&c_hat);
  ntt_of_identity(&h_hat, id, idlen);
  gen_matrix(A, pk->rho);
  for (i = 0; i < IBK; i++) {
    t_hat[i] = pk->t[i];
    poly_ntt(&t_hat[i]);
  }
  for (i = 0; i < IBK; i++) {
    poly_pointwise_montgomery(&az, &A[i][0], &z_hat[0]);
    for (j = 1; j < IBL; j++) {
      poly_pointwise_montgomery(&tmp, &A[i][j], &z_hat[j]);
      poly_add(&az, &az, &tmp);
      poly_reduce(&az);
    }
    /* c*(h*t) is a triple product, so collapse h*t with one exact pair first: nesting two
       pointwise_montgomery calls would leave this term scaled by 2^-32 relative to A z. */
    ntt_mul(&ht, &h_hat, &t_hat[i]);
    poly_pointwise_montgomery(&ct, &c_hat, &ht);
    poly_sub(&az, &az, &ct);
    poly_reduce(&az);
    poly_invntt_tomont(&az);
    poly_freeze(&az);
    ibs_decompose(&hi[i], &low, &az);
  }
  pack_w(w2, hi, IBK);
  return memcmp(w2, sig->w, WBYTES) ? 3 : 0;
}

/* ------------------------------------------------------------------ benchmark driver */

static uint64_t now_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static uint64_t g_overhead;

static void measure_overhead(void) {
  uint64_t best = (uint64_t)-1;
  int i;
  for (i = 0; i < 2000; i++) {
    uint64_t a = __rdtsc(), b = __rdtsc();
    if (b - a < best) best = b - a;
  }
  g_overhead = best;
}

static ibs_pk g_pk;
static ibs_msk g_msk;
static ibs_usk g_usk, g_forged;
static ibs_signature g_sig;
static uint8_t g_id[IDLEN] = "IIOT-PLC-042";
static uint8_t g_mu[MSGLEN];

static int run_setup(void) { ibs_setup(&g_pk, &g_msk); return 0; }
static int run_extract(void) { ibs_extract(g_usk, &g_msk, g_id, IDLEN); return 0; }
static unsigned g_sign_ctr;

static int run_sign(void) {
  /* a fresh message per call: y is bound to (id, mu, attempt), so signing the same mu
     over and over would time ONE fixed rejection trace (it varies from 5 to 70 attempts)
     instead of the expected cost. */
  g_mu[0] = (uint8_t)(g_sign_ctr & 0xff);
  g_mu[1] = (uint8_t)(g_sign_ctr >> 8);
  g_sign_ctr++;
  return ibs_sign(&g_sig, &g_pk, g_usk, g_id, IDLEN, g_mu, MSGLEN, 1u << 20);
}
static int run_verify(void) {
  return ibs_verify(&g_sig, &g_pk, g_id, IDLEN, g_mu, MSGLEN);
}

static double g_attempts_sum;
static long g_attempts_n;

static void bench(const char *name, int (*fn)(void), long iters) {
  uint64_t min_c = (uint64_t)-1, sum_c = 0, min_ns = (uint64_t)-1, sum_ns = 0;
  volatile int rc = 0;
  long i;
  g_attempts_sum = 0;
  g_attempts_n = 0;
  for (i = 0; i < iters; i++) {
    uint64_t c0 = __rdtsc(), t0 = now_ns();
    rc = fn();
    uint64_t c1 = __rdtsc(), t1 = now_ns();
    uint64_t dc = c1 - c0 - g_overhead, dn = t1 - t0;
    if (name[0] == 's' && name[1] == 'i') { g_attempts_sum += (double)g_attempts; g_attempts_n++; }
    if (dc < min_c) min_c = dc;
    if (dn < min_ns) min_ns = dn;
    sum_c += dc;
    sum_ns += dn;
  }
  (void)rc;
  printf("IBS-K2L2,%s,%ld,%.0f,%.0f,%.1f,%.1f,%d\n", name, iters,
         (double)min_c, (double)sum_c / iters,
         (double)min_ns / 1000.0, (double)sum_ns / (1000.0 * iters), rc);
  if (g_attempts_n)
    fprintf(stderr, "# %s: %.2f rejection attempts per accepted signature\n",
            name, g_attempts_sum / (double)g_attempts_n);
}

/* extended Euclid, only used by the F1 demonstration */
static int32_t modinv(int32_t a) {
  int64_t t = 0, newt = 1, r = Q, newr = a;
  while (newr) {
    int64_t q = r / newr, tmp;
    tmp = t - q * newt; t = newt; newt = tmp;
    tmp = r - q * newr; r = newr; newr = tmp;
  }
  t %= Q;
  if (t < 0) t += Q;
  return (int32_t)t;
}

int main(int argc, char **argv) {
  long iters = argc > 1 ? atol(argv[1]) : 200;
  int rc, i;
  unsigned j;
  poly h_hat, s1_hat[IBL];

  measure_overhead();
  for (i = 0; i < MSGLEN; i++) g_mu[i] = (uint8_t)i;

  printf("scheme,operation,iters,cycles_min,cycles_mean,us_min,us_mean,rc\n");

  /* ---- correctness: honest round trip, then three negative tests ---- */
  ibs_setup(&g_pk, &g_msk);
  ibs_extract(g_usk, &g_msk, g_id, IDLEN);
  if (ibs_sign(&g_sig, &g_pk, g_usk, g_id, IDLEN, g_mu, MSGLEN, 1u << 20)) {
    fprintf(stderr,
            "honest signature failed to be produced - aborting\n"
            "#   attempts %ld, rejected on LowBits %ld, rejected on |z| %ld, "
            "max|LowBits| seen %d (bound %d), max|y| %d, max|z| %d (bound %d)\n",
            g_attempts, g_rej_w, g_rej_z, g_diag_maxlo, ABORT_W, g_diag_maxy,
            g_diag_maxz, ABORT_Z);
    return 1;
  }
  if (ibs_verify(&g_sig, &g_pk, g_id, IDLEN, g_mu, MSGLEN)) {
    fprintf(stderr, "honest signature failed to verify - aborting\n");
    return 1;
  }
  fprintf(stderr, "# sign/verify round trip OK (%ld attempts)\n", g_attempts);
  g_mu[7] ^= 1;
  rc = ibs_verify(&g_sig, &g_pk, g_id, IDLEN, g_mu, MSGLEN);
  fprintf(stderr, "# tampered message rejected = %s (code %d)\n", rc ? "yes" : "NO", rc);
  g_mu[7] ^= 1;
  g_id[3] ^= 1;
  rc = ibs_verify(&g_sig, &g_pk, g_id, IDLEN, g_mu, MSGLEN);
  fprintf(stderr, "# signature valid under a different identity = %s (code %d)\n",
          rc ? "no (rejected)" : "YES", rc);
  g_id[3] ^= 1;
  g_sig.z[0].coeffs[5] += 1;
  rc = ibs_verify(&g_sig, &g_pk, g_id, IDLEN, g_mu, MSGLEN);
  fprintf(stderr, "# tampered response coefficient accepted = %s (code %d)\n",
          rc ? "no (rejected)" : "YES", rc);
  g_sig.z[0].coeffs[5] -= 1;

  /* ---- F1, natively: one issued key reveals the PKG master secret s1 ---- */
  ntt_of_identity(&h_hat, g_id, IDLEN);
  poly_freeze(&h_hat);
  for (j = 0; j < IBL; j++) {
    unsigned k;
    poly rec = g_usk[j];
    poly_freeze(&rec);
    for (k = 0; k < N; k++) {
      if (h_hat.coeffs[k] == 0) {
        fprintf(stderr, "# h not invertible at slot %u of %u\n", k, j);
        return 3;
      }
      /* usk = NTT(h) o NTT(s1) pointwise, so division in the NTT domain gives back s1 */
      s1_hat[j].coeffs[k] =
          (int32_t)((int64_t)rec.coeffs[k] * modinv(h_hat.coeffs[k]) % Q);
    }
  }
  {
    int s1_exact = 1;
    int nbad = 0;
    for (j = 0; j < IBL; j++) {
      poly truth = g_msk.s1[j];
      unsigned k;
      poly_ntt(&truth);
      poly_freeze(&truth);
      for (k = 0; k < N; k++)
        if (truth.coeffs[k] != s1_hat[j].coeffs[k]) {
          if (nbad == 0)
            fprintf(stderr, "#   first mismatch j=%u k=%u: rec=%d h^=%d truth=%d got=%d"
                    "  truth*h^%%q=%lld\n", j, k,
                    g_usk[j].coeffs[k], h_hat.coeffs[k], truth.coeffs[k],
                    s1_hat[j].coeffs[k],
                    (long long)((int64_t)truth.coeffs[k] * h_hat.coeffs[k] % Q));
          nbad++;
          s1_exact = 0;
        }
    }
    fprintf(stderr, "# F1: s1 recovered from one issued usk bit-exactly = %s (%d/%d slots differ)\n",
            s1_exact ? "yes" : "NO", nbad, 2 * N);
    if (!s1_exact) return 5;
  }
  {
    uint8_t victim[IDLEN] = "IIOT-GW-9999";
    poly vh;
    ntt_of_identity(&vh, victim, IDLEN);
    for (j = 0; j < IBL; j++) ntt_mul(&g_forged[j], &vh, &s1_hat[j]);
    ibs_sign(&g_sig, &g_pk, g_forged, victim, IDLEN, g_mu, MSGLEN, 1u << 20);
    rc = ibs_verify(&g_sig, &g_pk, victim, IDLEN, g_mu, MSGLEN);
    fprintf(stderr, "# F1: forgery for an identity the PKG never issued verifies = %s\n",
            rc ? "no" : "YES");
    if (rc) return 2;
  }

  /* ---- distribution check: the rejection rates have to match the theory, otherwise
         the cycle counts below would be measuring a scheme that does not mask properly ---- */
  {
    unsigned t;
    const int NT = 300;
    double asum = 0;
    int32_t lo_min = (int32_t)1 << 30, lo_max = 0;
    long reject_w, reject_z;
    g_rej_w = g_rej_z = 0;
    for (t = 0; t < NT; t++) {
      g_mu[0] = (uint8_t)t;
      g_diag_maxlo = 0;
      if (ibs_sign(&g_sig, &g_pk, g_usk, g_id, IDLEN, g_mu, MSGLEN, 1u << 20)) {
        fprintf(stderr, "# distribution check aborted at trial %u\n", t);
        return 4;
      }
      asum += (double)g_attempts;
      if (g_diag_maxlo < lo_min) lo_min = g_diag_maxlo;
      if (g_diag_maxlo > lo_max) lo_max = g_diag_maxlo;
    }
    reject_w = g_rej_w;
    reject_z = g_rej_z;
    fprintf(stderr,
            "# distribution check over %u signatures: mean attempts %.2f (theory ~%.1f), "
            "%ld rejections from |LowBits(Ay)| and %ld from |z|; "
            "max|LowBits(Ay)| of the first attempt in [%d, %d] against an abort bound of %d, "
            "max|y| %d (eta_y %d), max|z| %d (abort bound %d)\n",
            NT, asum / NT,
            1.0 / pow(1.0 - 2.0 * (GAMMA2 - ABORT_W) / (double)ALPHA, (double)IBK * N),
            reject_w, reject_z,
            lo_min, lo_max, ABORT_W, g_diag_maxy, ETA_Y, g_diag_maxz, ABORT_Z);
  }

  /* ---- sizes ---- */
  fprintf(stderr, "# sizes: mpk=%d B (rho %d + t %d x 3B), usk=%d B, sigma=%d B "
          "(w %d + z %d)\n",
          (int)(SEEDBYTES + IBK * N * 3), (int)SEEDBYTES, IBK * N,
          (int)(IBL * N * 3), (int)(WBYTES + IBL * N * 3), (int)WBYTES, IBL * N * 3);

  bench("keypair", run_setup, iters > 100 ? 100 : iters);
  bench("extract", run_extract, iters);
  bench("sign", run_sign, iters);
  bench("verify", run_verify, iters);
  return 0;
}
