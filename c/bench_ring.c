/* Cost of the individual ring kernels the identity-based signature of ch.4-4 is built
 * from.  Measured on the ring the scheme actually uses - n = 256, q = 8380417,
 * X^256 + 1, the vendored pq-crystals DILITHIUM arithmetic - so these numbers price
 * c/ibs.c and lab/ibs.py correctly.  (The Kyber reference has the same NTT shape over
 * q = 3329 with int16 coefficients and is markedly cheaper per kernel, so it must not be
 * used to price a q = 8380417 scheme.)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#include "params.h"
#include "poly.h"
#include "packing.h"
#include "rounding.h"
#include "fips202.h"

#define LABEL "ring-n256-q8380417 (dilithium ref)"
#define ITERS 200000

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
        do { c1 = __rdtsc(); t1 = now_ns(); } while (t1 - t0 < 20ull * 1000 * 1000);
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

static poly a, b, c, d;
static uint8_t seed[CRHBYTES] = {0}, cs[CTILDEBYTES] = {0};
static uint8_t out[N * 3];

static int r_ntt(void)       { memcpy(&c, &a, sizeof(poly)); poly_ntt(&c); return 0; }
static int r_invntt(void)    { memcpy(&c, &a, sizeof(poly)); poly_invntt_tomont(&c);
                               poly_reduce(&c); return 0; }
static int r_basemul(void)   { poly_pointwise_montgomery(&c, &a, &b); return 0; }
static int r_gamma1(void)    { poly_uniform_gamma1(&c, seed, 7); return 0; }
static int r_uniform(void)   { poly_uniform(&c, seed, 7); return 0; }
static int r_eta(void)       { poly_uniform_eta(&c, seed, 7); return 0; }
static int r_challenge(void) { poly_challenge(&c, cs); return 0; }
static int r_zpack(void)     { polyz_pack(out, &a); return 0; }
static int r_zunpack(void)   { polyz_unpack(&c, out); return 0; }
static int r_w1pack(void)    { polyw1_pack(out, &c); return 0; }
static int r_decompose(void) { poly_decompose(&c, &d, &a); return 0; }
static int r_reduce(void)    { poly_reduce(&c); return 0; }
static int r_shake128_32(void)  { shake128(out, 32, seed, 32); return 0; }
static int r_shake128_128(void) { shake128(out, 128, seed, 32); return 0; }
static int r_shake256_128(void) { shake256(out, 128, seed, 32); return 0; }

static void bench(const char *name, int (*fn)(void), long iters) {
    uint64_t min_c = (uint64_t)-1, sum_c = 0, min_ns = (uint64_t)-1, sum_ns = 0;
    for (long i = 0; i < iters; i++) {
        uint64_t t0 = now_ns(), c0 = __rdtsc();
        fn();
        uint64_t c1 = __rdtsc(), t1 = now_ns();
        uint64_t dc = c1 - c0 - g_overhead, dn = t1 - t0;
        if (dc < min_c) min_c = dc;
        if (dn < min_ns) min_ns = dn;
        sum_c += dc; sum_ns += dn;
    }
    printf("%s,%s,%ld,%.0f,%.0f,%.3f,%.3f,0\n", LABEL, name, iters,
           (double)min_c, (double)sum_c / iters,
           (double)min_ns / 1000.0, (double)sum_ns / (1000.0 * iters));
}

int main(int argc, char **argv) {
    long iters = argc > 1 ? atol(argv[1]) : ITERS;
    unsigned i;
    calibrate();
    measure_overhead();
    fprintf(stderr, "# %s tsc=%.2f Mticks/s overhead=%llu\n",
            LABEL, tsc_per_ns, (unsigned long long)g_overhead);
    printf("scheme,operation,iters,cycles_min,cycles_mean,us_min,us_mean,rc\n");
    memset(&a, 0, sizeof(a)); memset(&b, 0, sizeof(b)); memset(&c, 0, sizeof(c));
    for (i = 0; i < N; i++) {
        a.coeffs[i] = (int32_t)(i * 7 + 1);
        b.coeffs[i] = (int32_t)(i + 3);
    }
    poly_ntt(&a);
    poly_reduce(&b);
    memcpy(&c, &a, sizeof(poly));
    polyz_pack(out, &a);
    for (i = 0; i < N; i++) c.coeffs[i] = (int32_t)(i % 44);
    bench("poly_ntt", r_ntt, iters);
    bench("poly_invntt_tomont", r_invntt, iters);
    bench("poly_basemul_montgomery", r_basemul, iters);
    bench("poly_uniform", r_uniform, iters);
    bench("poly_uniform_eta", r_eta, iters);
    bench("poly_uniform_gamma1", r_gamma1, iters);
    bench("poly_challenge", r_challenge, iters);
    bench("poly_decompose", r_decompose, iters);
    bench("polyz_pack", r_zpack, iters);
    bench("polyz_unpack", r_zunpack, iters);
    bench("polyw1_pack", r_w1pack, iters);
    bench("poly_reduce", r_reduce, iters);
    bench("shake128_32B_out", r_shake128_32, iters);
    bench("shake128_128B_out", r_shake128_128, iters);
    bench("shake256_128B_out", r_shake256_128, iters);
    return 0;
}
