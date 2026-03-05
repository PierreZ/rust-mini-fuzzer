#!/usr/bin/env bash
# RUSTC_WRAPPER that injects SanitizerCoverage flags only for the mini_fuzzer crate.
#
# Only the binary crate gets instrumented — sancov_rt provides the callback
# implementations and must NOT be instrumented (it would create circular references).

set -euo pipefail

RUSTC="$1"
shift

CRATE_NAME=""
prev=""
for arg in "$@"; do
    if [[ "$prev" == "--crate-name" ]]; then
        CRATE_NAME="$arg"
        break
    fi
    prev="$arg"
done

if [[ "$CRATE_NAME" == "mini_fuzzer" ]]; then
    exec "$RUSTC" "$@" \
        -C passes=sancov-module \
        -C llvm-args=--sanitizer-coverage-level=3 \
        -C llvm-args=--sanitizer-coverage-inline-8bit-counters \
        -C llvm-args=--sanitizer-coverage-pc-table
else
    exec "$RUSTC" "$@"
fi
