/* Native benchmark of the reference lattice signature that stands in as the cost model for
 * the thesis' identity-based signature (no public code exists for the Zhichao et al. IBS,
 * so Dilithium-2 gives the measurable lattice baseline: same NTT size, same q structure,
 * one extra public h*s1 multiplication per verify).
 * Built with -DSCHEME=pqcrystals_dilithium2_ref -DDILITHIUM_MODE=2.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "api.h"
#include "randombytes.h"

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define F(name) CAT(SCHEME, name)

int F(_keypair)(uint8_t *pk, uint8_t *sk);
int F(_signature)(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                  const uint8_t *ctx, size_t ctxlen, const uint8_t *sk);
int F(_verify)(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
               const uint8_t *ctx, size_t ctxlen, const uint8_t *pk);

#if DILITHIUM_MODE == 2
#define PKBYTES pqcrystals_dilithium2_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_dilithium2_ref_SECRETKEYBYTES
#define SIGBYTES pqcrystals_dilithium2_ref_BYTES
#elif DILITHIUM_MODE == 3
#define PKBYTES pqcrystals_dilithium3_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_dilithium3_ref_SECRETKEYBYTES
#define SIGBYTES pqcrystals_dilithium3_ref_BYTES
#else
#define PKBYTES pqcrystals_dilithium5_ref_PUBLICKEYBYTES
#define SKBYTES pqcrystals_dilithium5_ref_SECRETKEYBYTES
#define SIGBYTES pqcrystals_dilithium5_ref_BYTES
#endif

#define MSGLEN 57                 /* |M1| in the protocol: IDA||IDB||pkAe||NA */

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static double tsc_per_ns = 1.0;
static void calibrate(void) {
    uint64_t best_c = 0, best_t = 0;
    for (int i = 0; i < 6; i++) {
        uint64_t c0 = __rdtsc(), t0 = now_ns(), c1, t1;
        do { c1 = __rdtsc(); t1 = now_ns(); } while (t1 - t0 < 30ull * 1000 * 1000);
        if (t1 - t0 > best_t) { best_t = t1 - t0; best_c = c1 - c0; }
    }
    tsc_per_ns = (double)best_c / (double)best_t;
}

static uint64_t g_overhead;
static void measure_overhead(void) {
    uint64_t best = (uint64_t)-1;
    for (int i = 0; i < 2000; i++) {
        uint64_t a = __rdtsc(), b = __rdtsc();
        if (b - a < best) best = b - a;
    }
    g_overhead = best;
}

static uint8_t pk[PKBYTES], sk[SKBYTES], sig[SIGBYTES], msg[MSGLEN];
static size_t siglen;

static int run_keypair(void) { return F(_keypair)(pk, sk); }
static int run_sign(void) {
    return F(_signature)(sig, &siglen, msg, MSGLEN, NULL, 0, sk);
}
static int run_verify(void) {
    return F(_verify)(sig, siglen, msg, MSGLEN, NULL, 0, pk);
}

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
        sum_c += dc; sum_ns += dn;
    }
    (void)rc;
    printf("%s,%s,%ld,%.0f,%.0f,%.1f,%.1f,%d\n", LABEL, name, iters,
           (double)min_c, (double)sum_c / iters,
           (double)min_ns / 1000.0, (double)sum_ns / (1000.0 * iters), rc);
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : 2000;
    calibrate();
    measure_overhead();
    fprintf(stderr, "# %s  tsc=%.2f Mticks/s  overhead=%llu cycles\n",
            LABEL, tsc_per_ns, (unsigned long long)g_overhead);
    printf("scheme,operation,iters,cycles_min,cycles_mean,us_min,us_mean,rc\n");
    F(_keypair)(pk, sk);
    F(_signature)(sig, &siglen, msg, MSGLEN, NULL, 0, sk);
    if (F(_verify)(sig, siglen, msg, MSGLEN, NULL, 0, pk) != 0) {
        fprintf(stderr, "honest signature failed to verify - aborting\n");
        return 1;
    }
    /* tamper: one bit of the message must break verification */
    msg[0] ^= 1;
    if (F(_verify)(sig, siglen, msg, MSGLEN, NULL, 0, pk) == 0) {
        fprintf(stderr, "WARNING: forged verification accepted\n");
    }
    msg[0] ^= 1;
    bench("keypair", run_keypair, iters > 200 ? 200 : iters);
    bench("sign", run_sign, iters);
    bench("verify", run_verify, iters);
    return 0;
}
