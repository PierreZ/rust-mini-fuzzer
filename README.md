# rust-mini-fuzzer

A minimal coverage-guided fuzzer in ~600 lines of Rust, built to understand how tools like [AFL](https://lcamtuf.coredump.cx/afl/) and [Antithesis](https://antithesis.com/) use code coverage to steer mutations toward bugs.

Companion code for the blogpost: **[Diving Into Coverage-Guided Fuzzing](https://pierrezemb.fr/posts/diving-into-coverage-guided-fuzzing/)**.

## The idea

The target function panics only when the first three bytes are `F`, `U`, `Z` in sequence. A random fuzzer needs ~16 million attempts (256³) to guess all three bytes at once. A coverage-guided fuzzer breaks this into three independent searches of ~256 each: discover `F` (new branch → save to corpus), then mutate from there to find `U`, then `Z`. **Coverage turns a multiplicative problem into an additive one.**

## Project structure

The project is a three-crate workspace. Only the target gets instrumented — keeping the fuzzer's own code out of the coverage map so it doesn't drown out the signal.

```
rust-mini-fuzzer/
├── fuzz-target/          # The function being fuzzed (instrumented by SanitizerCoverage)
├── sancov-rt/            # SanitizerCoverage runtime: LLVM callbacks, AFL-style bucketing, novelty detection
├── mini-fuzzer/          # Fuzzer engine: mutation loop, corpus management
└── rustc-sancov-wrapper.sh  # RUSTC_WRAPPER that injects sancov flags only for fuzz-target
```

## Building and running

```bash
# Enter the Nix dev shell (provides Rust + llvm-tools-preview)
nix develop

# Run the fuzzer
cargo run --release
```

## Sample output

```
[sancov] 8-bit counters registered: 10 edges
[init] 10 edges instrumented

#0       NEW  input="[0x00, 0x00, '-']" (3B)   corpus=2  edges=2/10  (20.0%)
#3       NEW  input="[0x00, 0x00]" (2B)         corpus=3  edges=3/10  (30.0%)
#1876    NEW  input="['F', 0x00, 0x00]" (3B)    corpus=4  edges=4/10  (40.0%)
#6743    NEW  input="['F', 'U', 0x00]" (3B)     corpus=5  edges=5/10  (50.0%)
#9066    CRASH! input="['F', 'U', 'Z', 0x00]" (4B)

== fuzzing complete ==
  iterations : 9067
  corpus size: 5
  edges hit  : 5 / 10  (50.0%)
  crash found: YES
```

9,000 iterations instead of 16 million.

## How it works

1. **Instrument** — A `RUSTC_WRAPPER` script injects LLVM's [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) pass only when compiling `fuzz-target`, adding a counter to every control-flow edge.
2. **Mutate** — Pick a random input from the corpus, apply a random mutation (insert, flip, or erase a byte).
3. **Execute** — Zero the counters, run the target, snapshot the counters.
4. **Classify** — Apply AFL-style hit-count bucketing to filter noise (37 hits and 38 hits both map to bucket 64).
5. **Select** — If any edge reached a higher bucket than ever seen before (max-reduce), the input is novel — add it to the corpus.
6. **Repeat** — Until a crash is found or the iteration limit is reached.

## Dependencies

Only two external crates: `rand` for mutations and `backtrace` for symbolizing edge addresses.
