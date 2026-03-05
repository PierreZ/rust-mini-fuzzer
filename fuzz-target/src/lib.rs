//! Fuzz target with progressively harder-to-reach code paths.
//!
//! This crate is intentionally separated from the fuzzer engine so that
//! **only this code gets instrumented** by the SanitizerCoverage pass.
//! This way, the edge count reported by the fuzzer reflects only the
//! target's complexity — not the fuzzer's own mutation/formatting code
//! or monomorphized standard library generics.
//!
//! The target is designed to demonstrate how coverage-guided fuzzing
//! discovers nested branches incrementally:
//!
//! 1. The first byte (`data[0] % 4`) selects one of four **entry paths**
//! 2. Each path has its own depth and branching logic
//! 3. One path ([`path_beta`]) contains a **magic byte sequence** (`F`, `U`, `Z`)
//!    that triggers a panic — this is the "bug" the fuzzer is trying to find
//!
//! A random fuzzer would need to guess the exact bytes in sequence — roughly
//! 1 in 2²⁴ chance for a 4-byte input. A coverage-guided fuzzer discovers
//! each layer independently: first it finds an input where `data[0] % 4 == 1`,
//! then one where `data[1] == 'F'`, then `data[2] == 'U'`, and finally
//! `data[3] == 'Z'`.

/// The function we're fuzzing. It has nested conditions that are
/// progressively harder to reach with random inputs, plus some
/// additional branching for a richer coverage landscape.
///
/// A coverage-guided fuzzer will discover the paths incrementally:
/// first the outer branches, then deeper nesting as it mutates
/// inputs that already reached partial matches.
#[inline(never)]
pub fn target(data: &[u8]) -> &'static str {
    if data.is_empty() {
        return "empty";
    }

    // A simple state machine with four entry paths
    match data[0] % 4 {
        0 => path_alpha(data),
        1 => path_beta(data),
        2 => path_gamma(data),
        _ => path_delta(data),
    }
}

/// **Alpha path** — branches on byte magnitude.
///
/// Requires at least 3 bytes. Checks whether `data[1]` is above or
/// below 128, producing two distinct coverage edges.
#[inline(never)]
fn path_alpha(data: &[u8]) -> &'static str {
    if data.len() < 3 {
        return "alpha-short";
    }
    if data[1] > 128 {
        "alpha-high"
    } else {
        "alpha-low"
    }
}

/// **Beta path** — the crash target with nested magic byte checks.
///
/// This is the classic fuzzer challenge: each byte must match a specific
/// value to go deeper. The fuzzer must discover `'F'`, then `'U'`, then
/// `'Z'` — each guarded by its own branch. A coverage-guided fuzzer
/// finds these incrementally because each partial match creates new
/// coverage that gets preserved in the corpus.
///
/// # Panics
///
/// Panics when `data[1..4] == [b'F', b'U', b'Z']` — this is the
/// intentional "bug" the fuzzer is searching for.
#[inline(never)]
fn path_beta(data: &[u8]) -> &'static str {
    if data.len() < 4 {
        return "beta-short";
    }
    // Nested magic byte checks — the classic fuzzer challenge.
    // Each level is guarded by a specific byte value.
    if data[1] == b'F' {
        if data[2] == b'U' {
            if data[3] == b'Z' {
                panic!("BOOM! Found the magic sequence: FUZZ");
            }
            return "beta-FU";
        }
        return "beta-F";
    }
    "beta-miss"
}

/// **Gamma path** — arithmetic check over all bytes.
///
/// Sums all bytes and branches on thresholds (256, 512). This tests
/// whether the fuzzer can discover inputs with specific aggregate
/// properties, not just specific byte values.
#[inline(never)]
fn path_gamma(data: &[u8]) -> &'static str {
    if data.len() < 2 {
        return "gamma-short";
    }
    // Arithmetic check — coverage sees different edges for the branches
    let sum: u16 = data.iter().map(|&b| b as u16).sum();
    if sum > 512 {
        "gamma-big"
    } else if sum > 256 {
        "gamma-medium"
    } else {
        "gamma-small"
    }
}

/// **Delta path** — loop with data-dependent iteration count.
///
/// Accumulates bytes greater than 100, then branches on whether the
/// total exceeds 1000. Different inputs produce different loop iteration
/// counts, which means different AFL hit-count buckets — even inputs
/// that take the same final branch can produce new coverage by changing
/// *how many times* the loop body executes.
#[inline(never)]
fn path_delta(data: &[u8]) -> &'static str {
    if data.len() < 5 {
        return "delta-short";
    }
    // Loop with data-dependent iteration count — different inputs
    // hit the loop edge different numbers of times, producing
    // different AFL buckets.
    let mut acc = 0u32;
    for &b in &data[1..] {
        if b > 100 {
            acc += b as u32;
        }
    }
    if acc > 1000 {
        "delta-hot"
    } else {
        "delta-cold"
    }
}
