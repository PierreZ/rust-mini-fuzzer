//! Fuzz target with a nested magic-byte sequence.
//!
//! This crate is intentionally separated from the fuzzer engine so that
//! **only this code gets instrumented** by the SanitizerCoverage pass.
//! This way, the edge count reported by the fuzzer reflects only the
//! target's complexity — not the fuzzer's own mutation/formatting code
//! or monomorphized standard library generics.
//!
//! The target demonstrates how coverage-guided fuzzing discovers nested
//! branches incrementally: each byte must match a specific value to go
//! deeper. A coverage-guided fuzzer finds these one at a time because
//! each partial match creates new coverage that gets preserved in the
//! corpus.
//!
//! A random fuzzer would need to guess the exact bytes in sequence —
//! roughly 1 in 2²⁴ chance for a 3-byte input. A coverage-guided
//! fuzzer discovers each layer independently: first it finds an input
//! where `data[0] == b'F'`, then `data[1] == b'U'`, and finally
//! `data[2] == b'Z'`.

/// The function we're fuzzing. It has nested magic-byte checks that
/// are progressively harder to reach with random inputs.
///
/// A coverage-guided fuzzer will discover the layers incrementally:
/// first `'F'`, then `'U'`, then `'Z'` — each guarded by its own
/// branch. Each partial match creates new coverage that gets
/// preserved in the corpus.
///
/// # Panics
///
/// Panics when `data[0..3] == [b'F', b'U', b'Z']` — this is the
/// intentional "bug" the fuzzer is searching for.
#[inline(never)]
pub fn target(data: &[u8]) -> &'static str {
    if data.len() < 3 {
        return "too-short";
    }
    if data[0] == b'F' {
        if data[1] == b'U' {
            if data[2] == b'Z' {
                panic!("BOOM! Found the magic sequence: FUZ");
            }
            return "partial-FU";
        }
        return "partial-F";
    }
    "miss"
}
