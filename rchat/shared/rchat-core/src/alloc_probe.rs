//! Test-only allocator probe (N-3): while armed on the current thread,
//! every buffer freed is scanned for a run of 128 ASCII hex digits (a seed
//! in hex), so a test can prove no seed copy is freed unwiped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

/// The process-wide needle (`freed_containing_any_thread`): armed flag,
/// the 32 bytes as four words, and the hits.
static GLOBAL_ARMED: AtomicBool = AtomicBool::new(false);
static GLOBAL_NEEDLE: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static GLOBAL_HITS: AtomicUsize = AtomicUsize::new(0);
/// One process-wide probe at a time.
static GLOBAL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn global_needle() -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, w) in GLOBAL_NEEDLE.iter().enumerate() {
        n[i * 8..i * 8 + 8].copy_from_slice(&w.load(Ordering::SeqCst).to_le_bytes());
    }
    n
}

struct Probe;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static HITS: Cell<usize> = const { Cell::new(0) };
    static NEEDLE: Cell<Option<[u8; 32]>> = const { Cell::new(None) };
    static NEEDLE_HITS: Cell<usize> = const { Cell::new(0) };
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATED: Cell<usize> = const { Cell::new(0) };
}

fn has_hex_run(bytes: &[u8], min: usize) -> bool {
    let mut run = 0;
    for b in bytes {
        if b.is_ascii_hexdigit() {
            run += 1;
            if run >= min {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

// SAFETY: forwards to `System`; the scan only reads the block being freed,
// which is valid for `layout.size()` bytes until `System.dealloc`.
unsafe impl GlobalAlloc for Probe {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if COUNTING.try_with(Cell::get).unwrap_or(false) {
            let _ = ALLOCATED.try_with(|a| a.set(a.get().saturating_add(layout.size())));
        }
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            if has_hex_run(bytes, 128) {
                let _ = HITS.try_with(|h| h.set(h.get() + 1));
            }
            if let Some(needle) = NEEDLE.try_with(Cell::get).ok().flatten() {
                if bytes.windows(needle.len()).any(|w| w == needle) {
                    let _ = NEEDLE_HITS.try_with(|h| h.set(h.get() + 1));
                }
            }
        }
        if GLOBAL_ARMED.load(Ordering::SeqCst) {
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            let needle = global_needle();
            if bytes.windows(needle.len()).any(|w| w == needle) {
                GLOBAL_HITS.fetch_add(1, Ordering::SeqCst);
            }
        }
        System.dealloc(ptr, layout)
    }
}

#[global_allocator]
static PROBE: Probe = Probe;

/// Run `f` and count the buffers freed on this thread holding a hex seed.
pub(crate) fn freed_hex_seeds<F: FnOnce()>(f: F) -> usize {
    HITS.with(|h| h.set(0));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    HITS.with(Cell::get)
}

/// Run `f` and count the buffers freed on this thread that still contain
/// `needle` (32 bytes of a binary secret), so a test can prove a heap secret
/// is wiped before it is freed.
pub(crate) fn freed_containing<F: FnOnce()>(needle: [u8; 32], f: F) -> usize {
    NEEDLE_HITS.with(|h| h.set(0));
    NEEDLE.with(|n| n.set(Some(needle)));
    ARMED.with(|a| a.set(true));
    f();
    ARMED.with(|a| a.set(false));
    NEEDLE.with(|n| n.set(None));
    NEEDLE_HITS.with(Cell::get)
}

/// Run `f` and return the total bytes it allocated on this thread (every
/// allocation and reallocation counted in full, frees not subtracted), so a
/// test can bound what a parser allocates by its input (Task 13).
pub(crate) fn bytes_allocated<F: FnOnce()>(f: F) -> usize {
    ALLOCATED.with(|a| a.set(0));
    COUNTING.with(|c| c.set(true));
    f();
    COUNTING.with(|c| c.set(false));
    ALLOCATED.with(Cell::get)
}

/// `freed_containing` for buffers freed on **any** thread while `f` runs
/// (for code that hops to a runtime or worker thread). Use a random
/// needle: frees from other tests running meanwhile then cannot match.
pub(crate) fn freed_containing_any_thread<F: FnOnce()>(needle: [u8; 32], f: F) -> usize {
    let _one = GLOBAL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    for (i, w) in GLOBAL_NEEDLE.iter().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&needle[i * 8..i * 8 + 8]);
        w.store(u64::from_le_bytes(word), Ordering::SeqCst);
    }
    GLOBAL_HITS.store(0, Ordering::SeqCst);
    GLOBAL_ARMED.store(true, Ordering::SeqCst);
    f();
    GLOBAL_ARMED.store(false, Ordering::SeqCst);
    GLOBAL_HITS.load(Ordering::SeqCst)
}
