//! Minimal SanitizerCoverage runtime for inline-8bit-counters + pc-table.
//!
//! # What is SanitizerCoverage?
//!
//! [SanitizerCoverage](https://clang.llvm.org/docs/SanitizerCoverage.html) (sancov) is an
//! LLVM instrumentation pass that inserts lightweight callbacks at **control-flow edges**
//! (branches, loop entries, function entries). It is the foundation of coverage-guided
//! fuzzers like libFuzzer and honggfuzz.
//!
//! When compiled with `-C passes=sancov-module` and the right `llvm-args`, LLVM does two
//! things at link time:
//!
//! 1. **Allocates an array of 8-bit counters** — one byte per instrumented edge.
//!    Every time an edge is taken, the corresponding counter is incremented (saturating
//!    at 255). The runtime is notified of this array via
//!    [`__sanitizer_cov_8bit_counters_init`].
//!
//! 2. **Allocates a PC table** — an array of `(code_address, flags)` pairs, parallel to
//!    the counter array. `counters[i]` maps to `pc_table[i]`, which tells you *where* in
//!    the binary that edge lives. The runtime receives this via
//!    [`__sanitizer_cov_pcs_init`].
//!
//! This crate implements both callbacks, stores the pointers, and exposes safe accessors
//! for the fuzzer to read, reset, and snapshot the counters.
//!
//! # AFL-style hit-count bucketing
//!
//! Raw counters are noisy: an edge hit 37 times vs. 38 times is not meaningfully
//! different. AFL's insight is to **bucket** the counts into coarse classes (1, 2, 3,
//! 4–7, 8–15, …). This way, only *qualitative* changes in execution count register as
//! new coverage. See [`classify_counts`] and the [`COUNT_CLASS_LOOKUP`] table.
//!
//! # Novelty detection
//!
//! [`CoverageTracker`] maintains a **history map** of the maximum bucket seen for each
//! edge. An input is "interesting" if it causes any edge to reach a **higher bucket**
//! than previously observed — the max-reduce strategy from LibAFL.
//!
//! # Architecture note
//!
//! This crate must **not** be instrumented itself — it provides the callbacks that LLVM's
//! instrumentation calls into. Instrumenting it would create circular references. The
//! `rustc-sancov-wrapper.sh` script ensures only the `mini_fuzzer` crate gets the sancov
//! pass.

use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

// ---------------------------------------------------------------------------
// Global state — populated by LLVM's module constructors before main()
// ---------------------------------------------------------------------------

static COUNTERS_START: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
static COUNTERS_LEN: AtomicUsize = AtomicUsize::new(0);

static PC_TABLE_START: AtomicPtr<PcTableEntry> = AtomicPtr::new(std::ptr::null_mut());
static PC_TABLE_LEN: AtomicUsize = AtomicUsize::new(0);

/// One entry in the PC table. Maps 1:1 with the counter array:
/// `counters[i]` corresponds to `pc_table[i]`.
#[repr(C)]
pub struct PcTableEntry {
    /// Code address of the instrumented edge.
    pub pc: usize,
    /// Bit 0 = 1 means this edge is a function entry block.
    pub flags: usize,
}

// ---------------------------------------------------------------------------
// LLVM callbacks — called during static initialization, before main()
// ---------------------------------------------------------------------------

/// Called by LLVM's sancov pass to register the 8-bit counter array.
///
/// The region `[start, stop)` is a contiguous array with one byte per
/// instrumented edge. LLVM generates a call to this function in a module
/// constructor, so it runs before `main()`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_8bit_counters_init(start: *mut u8, stop: *mut u8) {
    let len = stop as usize - start as usize;
    COUNTERS_START.store(start, Ordering::SeqCst);
    COUNTERS_LEN.store(len, Ordering::SeqCst);
    eprintln!("[sancov] 8-bit counters registered: {len} edges at {start:?}..{stop:?}");
}

/// Called by LLVM's sancov pass to register the PC table.
///
/// Each entry is a `(pc, flags)` pair, parallel to the counter array.
/// This allows the fuzzer to map a counter index back to a code address
/// for reporting and symbolization.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __sanitizer_cov_pcs_init(pcs_beg: *const usize, pcs_end: *const usize) {
    let byte_len = pcs_end as usize - pcs_beg as usize;
    let entry_count = byte_len / std::mem::size_of::<PcTableEntry>();
    PC_TABLE_START.store(pcs_beg as *mut PcTableEntry, Ordering::SeqCst);
    PC_TABLE_LEN.store(entry_count, Ordering::SeqCst);
    eprintln!("[sancov] PC table registered: {entry_count} entries at {pcs_beg:?}..{pcs_end:?}");
}

// ---------------------------------------------------------------------------
// Safe accessors
// ---------------------------------------------------------------------------

/// Returns `true` if sancov instrumentation is active (counters were registered).
pub fn is_available() -> bool {
    !COUNTERS_START.load(Ordering::SeqCst).is_null() && COUNTERS_LEN.load(Ordering::SeqCst) > 0
}

/// Total number of instrumented edges.
pub fn edge_count() -> usize {
    COUNTERS_LEN.load(Ordering::SeqCst)
}

/// Number of edges hit (counter > 0) in the current counter state.
pub fn edges_hit() -> usize {
    counters().iter().filter(|&&c| c > 0).count()
}

/// Read-only view of the counter array. Empty if not available.
pub fn counters() -> &'static [u8] {
    let start = COUNTERS_START.load(Ordering::SeqCst);
    let len = COUNTERS_LEN.load(Ordering::SeqCst);
    if start.is_null() || len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(start, len) }
}

/// Read-only view of the PC table. Empty if not available.
pub fn pc_table() -> &'static [PcTableEntry] {
    let start = PC_TABLE_START.load(Ordering::SeqCst);
    let len = PC_TABLE_LEN.load(Ordering::SeqCst);
    if start.is_null() || len == 0 {
        return &[];
    }
    unsafe { std::slice::from_raw_parts(start, len) }
}

/// Zero all counters. Call this before each fuzz iteration so that the
/// counters reflect only the current input's execution.
pub fn reset() {
    let start = COUNTERS_START.load(Ordering::SeqCst);
    let len = COUNTERS_LEN.load(Ordering::SeqCst);
    if !start.is_null() && len > 0 {
        unsafe { std::ptr::write_bytes(start, 0, len) }
    }
}

/// Return a snapshot (owned copy) of the current counter values.
///
/// Take a snapshot *after* running the target but *before* resetting,
/// then pass it to [`classify_counts`] and [`CoverageTracker::has_new_coverage`].
pub fn snapshot() -> Vec<u8> {
    counters().to_vec()
}

// ---------------------------------------------------------------------------
// AFL-style hit-count bucketing
// ---------------------------------------------------------------------------

/// The AFL/libFuzzer bucketing table. Maps raw 8-bit counter values
/// to coarse buckets so that minor count variations don't produce
/// false "new coverage" signals.
///
/// | Raw count | Bucket | Meaning           |
/// |-----------|--------|-------------------|
/// | 0         | 0      | never executed    |
/// | 1         | 1      | once              |
/// | 2         | 2      | twice             |
/// | 3         | 4      | a few times       |
/// | 4–7       | 8      | small loop        |
/// | 8–15      | 16     | moderate loop     |
/// | 16–31     | 32     | many iterations   |
/// | 32–127    | 64     | heavy loop        |
/// | 128–255   | 128    | very heavy loop   |
const COUNT_CLASS_LOOKUP: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        table[i] = match i {
            0 => 0,
            1 => 1,
            2 => 2,
            3 => 4,
            4..=7 => 8,
            8..=15 => 16,
            16..=31 => 32,
            32..=127 => 64,
            _ => 128,
        };
        i += 1;
    }
    table
};

/// Apply AFL bucketing to a coverage buffer in-place.
///
/// Call this on the result of [`snapshot`] before passing it to
/// [`CoverageTracker::has_new_coverage`]. This collapses raw hit counts
/// into coarse buckets so that trivial count differences (37 vs 38 hits)
/// don't register as new coverage.
pub fn classify_counts(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        *b = COUNT_CLASS_LOOKUP[*b as usize];
    }
}

// ---------------------------------------------------------------------------
// Novelty detection — the core of coverage-guided fuzzing
// ---------------------------------------------------------------------------

/// Tracks the maximum bucketed coverage seen so far.
///
/// The key insight: an input is "interesting" if it causes any edge to
/// reach a **higher bucket** than previously observed. This is the
/// max-reduce from LibAFL's `covmap_is_interesting`.
///
/// # Example
///
/// ```ignore
/// let mut tracker = sancov_rt::CoverageTracker::new();
///
/// // After running target with some input:
/// let mut snap = sancov_rt::snapshot();
/// sancov_rt::classify_counts(&mut snap);
///
/// if tracker.has_new_coverage(&snap) {
///     // This input discovered new behavior — add to corpus
/// }
/// ```
pub struct CoverageTracker {
    history: Vec<u8>,
}

impl CoverageTracker {
    /// Create a tracker. Call after sancov is initialized (i.e., in `main()`).
    pub fn new() -> Self {
        let len = edge_count();
        Self {
            history: vec![0u8; len],
        }
    }

    /// Check if `current` (already bucketed via [`classify_counts`]) contains
    /// new coverage.
    ///
    /// Updates the history map for any new maximums found.
    /// Returns `true` if at least one edge reached a new (higher) bucket.
    pub fn has_new_coverage(&mut self, current: &[u8]) -> bool {
        let mut dominated = true;
        for (i, &val) in current.iter().enumerate() {
            if val == 0 {
                continue; // skip unexecuted edges — hot path optimization
            }
            if i < self.history.len() && val > self.history[i] {
                self.history[i] = val;
                dominated = false;
            }
        }
        !dominated
    }

    /// Number of edges that have been hit at least once across all inputs.
    pub fn total_edges_covered(&self) -> usize {
        self.history.iter().filter(|&&v| v > 0).count()
    }
}

// ---------------------------------------------------------------------------
// Symbolization
// ---------------------------------------------------------------------------

/// Resolve a code address to a human-readable symbol name.
///
/// Uses the `backtrace` crate to look up DWARF debug info. Strips Rust
/// crate hashes (the `[hex]` suffixes) for cleaner output.
pub fn symbolize(pc: usize) -> String {
    let mut name = format!("{pc:#x}");
    backtrace::resolve(pc as *mut std::ffi::c_void, |symbol| {
        if let Some(sym_name) = symbol.name() {
            name = format!("{sym_name}");
        }
    });
    // Strip Rust crate hashes like [1932e991d6aff445]
    while let Some(start) = name.find('[') {
        if let Some(end) = name[start..].find(']') {
            let content = &name[start + 1..start + end];
            if content.len() == 16 && content.chars().all(|c| c.is_ascii_hexdigit()) {
                name = format!("{}{}", &name[..start], &name[start + end + 1..]);
                continue;
            }
        }
        break;
    }
    while name.contains("::::") {
        name = name.replace("::::", "::");
    }
    name
}
