#!/bin/sh
# Native (x86-64) build of the lattice primitives the protocol is made of.
# Toolchain: Zig 0.17 as a C compiler driver (no MSVC/gcc needed).
# Sources: pq-crystals reference C - the same code family pqm4's "clean" rows measure,
# vendored under vendor/. pqm4's own m4fspeed kernels are Cortex-M4 assembly and cannot
# be compiled for x86; its published M4 cycle counts are taken from vendor/pqm4-src/benchmarks.csv.
set -e
cd "$(dirname "$0")"

ZIG="${ZIG:-/c/Users/DnT/AppData/Local/Microsoft/WinGet/Packages/zig.zig_Microsoft.Winget.Source_8wekyb3d8bbwe/zig-x86_64-windows-0.17.0/zig.exe}"
V=../vendor
K=$V/kyber/ref
D=$V/dilithium/ref
CFLAGS="-O3 -march=native -std=c11 -D_POSIX_C_SOURCE=200809L"
KSRC="$K/kem.c $K/indcpa.c $K/polyvec.c $K/poly.c $K/ntt.c $K/cbd.c $K/reduce.c $K/verify.c $K/fips202.c $K/symmetric-shake.c $K/randombytes.c"
DSRC="$D/sign.c $D/packing.c $D/polyvec.c $D/poly.c $D/ntt.c $D/reduce.c $D/rounding.c $D/fips202.c $D/symmetric-shake.c $D/randombytes.c"
# Dilithium's ring arithmetic alone (n=256, q=8380417): the kernel price table and the IBS.
RSRC="$D/poly.c $D/packing.c $D/polyvec.c $D/ntt.c $D/reduce.c $D/rounding.c $D/fips202.c $D/symmetric-shake.c $D/randombytes.c"

build() {
  out=$1; shift
  echo "  -> $out"
  rm -f "$out"          # never let a stale binary hide a compile failure
  # shellcheck disable=SC2086
  "$ZIG" cc $CFLAGS -o "$out" "$@" -ladvapi32 2>&1 | grep -v "^$" || true
  [ -f "$out" ] || { echo "BUILD FAILED: $out"; exit 1; }
}

echo "building native benchmarks"
build bench_kyber512.exe  -I"$K" bench_kem.c  $KSRC -DKYBER_K=2 -DSCHEME=pqcrystals_kyber512_ref  -DLABEL='"ML-KEM-512 (kyber512/ref)"'
build bench_kyber768.exe  -I"$K" bench_kem.c  $KSRC -DKYBER_K=3 -DSCHEME=pqcrystals_kyber768_ref  -DLABEL='"ML-KEM-768 (kyber768/ref)"'
build bench_dil2.exe      -I"$D" bench_sig.c  $DSRC -DDILITHIUM_MODE=2 -DSCHEME=pqcrystals_dilithium2_ref -DLABEL='"Dilithium-2 (ML-DSA-44 class)"'
build bench_dil3.exe      -I"$D" bench_sig.c  $DSRC -DDILITHIUM_MODE=3 -DSCHEME=pqcrystals_dilithium3_ref -DLABEL='"Dilithium-3 (ML-DSA-65 class)"'
build bench_ring.exe      -I"$D" bench_ring.c $RSRC -DDILITHIUM_MODE=2
# The ch.4-4 identity-based signature (K=L=2, n=256, q=8380417) on dilithium's ring kernels.
build bench_ibs.exe       -I"$D" ibs.c $RSRC -DDILITHIUM_MODE=2
echo "done"
