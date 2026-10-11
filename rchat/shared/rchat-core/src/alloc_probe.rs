//! Test-only allocator probe (N-3): while armed on the current thread,
//! every buffer freed is scanned for a run of 128 ASCII hex digits (a seed
//! in hex), so a test can prove no seed copy is freed unwiped.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct Probe;

thread_local! {
    static ARMED: Cell<bool> = const { Cell::new(false) };
    static HITS: Cell<usize> = const { Cell::new(0) };
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
        System.alloc(layout)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.try_with(Cell::get).unwrap_or(false) {
            let bytes = std::slice::from_raw_parts(ptr, layout.size());
            if has_hex_run(bytes, 128) {
                let _ = HITS.try_with(|h| h.set(h.get() + 1));
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
