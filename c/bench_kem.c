/* Native cycle/wall-clock benchmark of the KEM the protocol uses as its ratchet engine.
 * Built from the pq-crystals reference C (the same sources pqm4's clean rows derive from),
 * parameterised with -DSK -DSCHEME=pqcrystals_kyber512_ref -DKYBER_K=2.
 * Output: one CSV line per operation on stdout.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "api.h"
#include "fips202.h"
#include "randombytes.h"

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define F(name) CAT(SCHEME, name)

int F(_keypair)(uint8_t *pk, uint8_t *sk);
int F(_enc)(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int F(_dec)(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if KYBER_K == 2
#define PKBYTES pqcrystals_kyber512_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_kyber512_ref_SECRETKEYBYTES
#define CTBYTES pqcrystals_kyber512_ref_CIPHERTEXTBYTES
#define SSBYTES pqcrystals_kyber512_ref_BYTES
#elif KYBER_K == 3
#define PKBYTES pqcrystals_kyber768_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_kyber768_ref_SECRETKEYBYTES
#define CTBYTES pqcrystals_kyber768_ref_CIPHERTEXTBYTES
#define SSBYTES pqcrystals_kyber768_ref_BYTES
#else
#define PKBYTES pqcrystals_kyber1024_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_kyber1024_ref_SECRETKEYBYTES
#define CTBYTES pqcrystals_kyber1024_ref_CIPHERTEXTBYTES
#define SSBYTES pqcrystals_kyber1024_ref_BYTES
#endif

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

/* rdtsc counts at the invariant TSC rate, not the core clock: calibrate against the
 * monotonic clock once per run and report both. */
static double tsc_per_ns = 1.0;

static void calibrate(void) {
    uint64_t c0, t0, c1, t1, best_c = 0, best_t = 0;
    for (int i = 0; i < 6; i++) {
        c0 = __rdtsc();
        t0 = now_ns();
        do {
            c1 = __rdtsc();
            t1 = now_ns();
        } while (t1 - t0 < 30ull * 1000 * 1000);          /* 30 ms window */
        if (t1 - t0 > best_t) { best_t = t1 - t0; best_c = c1 - c0; }
    }
    tsc_per_ns = (double)best_c / (double)best_t;
}

static uint64_t g_overhead;

static void measure_overhead(void) {
    uint64_t best = (uint64_t)-1;
    for (int i = 0; i < 2000; i++) {
        uint64_t a = __rdtsc();
        uint64_t b = __rdtsc();
        if (b - a < best) best = b - a;
    }
    g_overhead = best;
}

typedef int (*op_fn)(void);
static op_fn g_op;

static int run_keypair(void) {
    static uint8_t pk[PKBYTES], sk[SKBYTES];
    return F(_keypair)(pk, sk);
}
static uint8_t pkbuf[PKBYTES], skbuf[SKBYTES], ctbuf[CTBYTES], ss1[SSBYTES], ss2[SSBYTES];

static int run_enc(void) { return F(_enc)(ctbuf, ss1, pkbuf); }
static int run_dec(void) { return F(_dec)(ss2, ctbuf, skbuf); }

static void bench(const char *name, int (*fn)(void), long iters) {
    uint64_t min_c = (uint64_t)-1, sum_c = 0, min_ns = (uint64_t)-1, sum_ns = 0;
    volatile int rc = 0;
    for (long i = 0; i < iters; i++) {
        uint64_t c0 = __rdtsc(), t0 = now_ns();
        rc = fn();
        uint64_t c1 = __rdtsc(), t1 = now_ns();
        uint64_t dc = c1 - c0 - g_overhead, dn = t1 - t0;
        if (dc < min_c) min_c = dc;
        if (dn < min_ns) min_ns = dn;
        sum_c += dc;
        sum_ns += dn;
    }
    (void)rc;
    printf("%s,%s,%ld,%.0f,%.0f,%.1f,%.1f,%d\n", LABEL, name, iters,
           (double)min_c, (double)sum_c / iters,
           (double)min_ns / 1000.0, (double)sum_ns / (1000.0 * iters), rc);
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 20000;
    calibrate();
    measure_overhead();
    fprintf(stderr, "# %s  tsc=%.2f Mticks/s  rdtsc overhead=%llu cycles\n",
            LABEL, tsc_per_ns, (unsigned long long)g_overhead);
    printf("scheme,operation,iters,cycles_min,cycles_mean,us_min,us_mean,rc\n");

    F(_keypair)(pkbuf, skbuf);
    F(_enc)(ctbuf, ss1, pkbuf);
    F(_dec)(ss2, ctbuf, skbuf);
    if (memcmp(ss1, ss2, SSBYTES) != 0) {
        fprintf(stderr, "EXPLICIT REJECTION MISMATCH - aborting benchmark\n");
        return 1;
    }
    bench("keypair", run_keypair, iters);
    bench("encaps", run_enc, iters);
    bench("decaps", run_dec, iters);

    /* cost of the symmetric layer the ratchet runs on every message */
    {
        static uint8_t out[32], in[32];
        uint64_t c0 = __rdtsc();
        for (long i = 0; i < iters; i++) { shake128(out, 32, in, 32); in[0] ^= out[0]; }
        uint64_t c1 = __rdtsc();
        printf("keccak,shake128_32B_out,%ld,%.0f,%.0f,%.3f,%.3f,0\n", iters,
               (double)(c1 - c0) / iters, (double)(c1 - c0) / iters,
               0.0, (double)(c1 - c0) / (iters * tsc_per_ns * 1000.0));
        c0 = __rdtsc();
        for (long i = 0; i < iters; i++) { shake256(out, 32, in, 32); in[0] ^= out[0]; }
        c1 = __rdtsc();
        printf("keccak,shake256_32B_out,%ld,%.0f,%.0f,%.3f,%.3f,0\n", iters,
               (double)(c1 - c0) / iters, (double)(c1 - c0) / iters,
               0.0, (double)(c1 - c0) / (iters * tsc_per_ns * 1000.0));
    }
    return 0;
}
