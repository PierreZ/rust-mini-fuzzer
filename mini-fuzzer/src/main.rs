//! A minimal coverage-guided fuzzer, built from first principles.
//!
//! # How coverage-guided fuzzing works
//!
//! Traditional "dumb" fuzzing generates random inputs and hopes to trigger bugs.
//! Coverage-guided fuzzing is smarter: it **observes which code paths** each input
//! exercises, and **keeps inputs that discover new paths**. Over time, the corpus
//! evolves toward deeper and deeper coverage.
//!
//! The feedback loop:
//!
//! ```text
//! ┌─────────┐    mutate    ┌─────────┐    run     ┌────────┐
//! │ corpus  │──────────────▶│  input  │───────────▶│ target │
//! └────▲────┘              └─────────┘            └───┬────┘
//!      │                                              │
//!      │  if new coverage                   coverage counters
//!      │                                              │
//!      └──────────────────────────────────────────────┘
//! ```
//!
//! 1. **Pick** a random input from the corpus and **mutate** it
//! 2. **Reset** the coverage counters, then **run** the target function
//! 3. **Snapshot** the counters, apply AFL bucketing, check for **novelty**
//! 4. If the input reached a new coverage bucket → **add it to the corpus**
//! 5. If the target **panicked** → we found a crash!
//!
//! # Two-crate architecture
//!
//! The project is split into two crates:
//!
//! - **`sancov-rt`** — The SanitizerCoverage runtime. It implements the LLVM callbacks
//!   that register counter arrays at startup, and provides safe APIs for the fuzzer to
//!   read/reset/snapshot the counters. This crate is **not instrumented**.
//!
//! - **`fuzz-target`** — The target function being fuzzed. This is the **only crate
//!   that gets instrumented** via `rustc-sancov-wrapper.sh`, so the edge count
//!   reflects only the target's complexity.
//!
//! - **`mini-fuzzer`** (this crate) — The fuzzer engine. It is **not instrumented**,
//!   so its own code doesn't pollute the coverage metrics.
//!
//! # Running
//!
//! ```bash
//! # Enter the nix dev shell (provides Rust + llvm-tools-preview)
//! nix develop
//!
//! # Build and run
//! cargo run
//! ```
//!
//! The fuzzer will discover coverage incrementally and eventually find the
//! magic `FUZZ` byte sequence that triggers a panic in the target.

use rand::Rng;
use std::panic;

fn main() {
    // Suppress panic backtraces — we catch panics intentionally
    panic::set_hook(Box::new(|_| {}));

    println!("=== Mini Coverage-Guided Fuzzer ===");
    println!();

    if !sancov_rt::is_available() {
        eprintln!("ERROR: SanitizerCoverage not active.");
        eprintln!("Make sure the RUSTC_WRAPPER is configured (see .cargo/config.toml).");
        std::process::exit(1);
    }

    let total_edges = sancov_rt::edge_count();
    println!("[init] {total_edges} edges instrumented");
    println!();

    let mut tracker = sancov_rt::CoverageTracker::new();
    let mut corpus: Vec<Vec<u8>> = vec![vec![]]; // seed: one empty input
    let mut rng = rand::rng();

    let max_iterations = 1_000_000;
    let mut crash_found = false;

    for iter in 0..max_iterations {
        // 1. Pick a base input from the corpus and mutate it
        let base_idx = rng.random_range(0..corpus.len());
        let input = mutate(&corpus[base_idx], &mut rng);

        // 2. Reset counters, then run the target
        sancov_rt::reset();
        let crashed = run_target(&input);

        if crashed {
            crash_found = true;
            println!(
                "#{iter:<6}  CRASH! input={:?} ({}B)  corpus={}  edges={}/{}",
                format_input(&input),
                input.len(),
                corpus.len(),
                tracker.total_edges_covered(),
                total_edges,
            );
            corpus.push(input);
            break;
        }

        // 3. Snapshot counters, apply AFL bucketing, check for novelty
        let mut snap = sancov_rt::snapshot();
        sancov_rt::classify_counts(&mut snap);

        if tracker.has_new_coverage(&snap) {
            let covered = tracker.total_edges_covered();
            let result = fuzz_target::target(&[]); // won't matter, just for display
            let _ = result;
            println!(
                "#{iter:<6}  NEW  input={:?} ({}B)  corpus={}  edges={}/{}  ({:.1}%)",
                format_input(&input),
                input.len(),
                corpus.len() + 1,
                covered,
                total_edges,
                covered as f64 / total_edges as f64 * 100.0,
            );
            corpus.push(input);
        }
    }

    // Final summary
    println!();
    println!("=== Summary ===");
    println!(
        "  Iterations:  {}",
        if crash_found {
            format!("stopped at crash")
        } else {
            format!("{max_iterations}")
        }
    );
    println!("  Corpus size: {}", corpus.len());
    println!(
        "  Edges:       {}/{} ({:.1}%)",
        tracker.total_edges_covered(),
        total_edges,
        tracker.total_edges_covered() as f64 / total_edges as f64 * 100.0,
    );
    println!("  Crash found: {crash_found}");
}

/// Run the target function, catching any panic. Returns `true` if it crashed.
///
/// Uses [`std::hint::black_box`] to prevent the compiler from optimizing away
/// the target call or its input — essential when the target's return value is
/// otherwise unused.
fn run_target(input: &[u8]) -> bool {
    let result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        std::hint::black_box(fuzz_target::target(std::hint::black_box(input)));
    }));
    result.is_err()
}

/// Mutate an input using one of three strategies, chosen at random:
///
/// - **Insert**: add a random byte at a random position (grows the input)
/// - **Flip**: replace a random byte with a random value (same length)
/// - **Erase**: remove a random byte (shrinks the input)
///
/// If the input is empty, always inserts (can't flip or erase nothing).
fn mutate(base: &[u8], rng: &mut impl Rng) -> Vec<u8> {
    let mut buf = base.to_vec();
    let strategy = if buf.is_empty() { 0 } else { rng.random_range(0..3u8) };

    match strategy {
        0 => {
            // Insert a random byte
            let pos = rng.random_range(0..=buf.len());
            let val: u8 = rng.random();
            buf.insert(pos, val);
        }
        1 => {
            // Flip a random byte
            let pos = rng.random_range(0..buf.len());
            buf[pos] = rng.random();
        }
        2 => {
            // Erase a random byte
            let pos = rng.random_range(0..buf.len());
            buf.remove(pos);
        }
        _ => unreachable!(),
    }
    buf
}

/// Format input bytes for display.
///
/// Short inputs (≤ 8 bytes) show each byte as `'c'` (if printable ASCII)
/// or `0xNN` (hex). Longer inputs show the length and first 6 bytes.
fn format_input(data: &[u8]) -> String {
    if data.len() <= 8 {
        let parts: Vec<String> = data
            .iter()
            .map(|&b| {
                if b.is_ascii_graphic() || b == b' ' {
                    format!("'{}'", b as char)
                } else {
                    format!("0x{b:02x}")
                }
            })
            .collect();
        format!("[{}]", parts.join(", "))
    } else {
        format!("[{}B: {:02x?}...]", data.len(), &data[..6])
    }
}
