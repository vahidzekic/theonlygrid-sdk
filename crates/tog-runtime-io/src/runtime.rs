//! Process-level pieces of a wasm32 runtime or verification blob: the bump allocator,
//! `tog_v1_alloc` and the panic handler. Each entry-point call runs in a fresh instance, so freeing
//! is never needed.

#![allow(unsafe_code)]

use core::alloc::{GlobalAlloc, Layout};
use core::cell::Cell;

const PAGE: usize = 64 << 10;

/// Bumps a pointer through memory grown on demand; `dealloc` does nothing.
struct Bump {
    next: Cell<usize>,
    end: Cell<usize>,
}

// SAFETY: wasm32 runtimes are single-threaded (threads are refused at pre-check).
unsafe impl Sync for Bump {}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let start = (self.next.get() + layout.align() - 1) & !(layout.align() - 1);
        let Some(new_next) = start.checked_add(layout.size()) else { return core::ptr::null_mut() };
        if start == 0 || new_next > self.end.get() {
            // First use or out of room: take fresh pages at the end of memory.
            let need = layout.size() + layout.align();
            let pages = need.div_ceil(PAGE);
            let prev = core::arch::wasm32::memory_grow(0, pages);
            if prev == usize::MAX {
                return core::ptr::null_mut();
            }
            let base = prev * PAGE;
            let start = (base + layout.align() - 1) & !(layout.align() - 1);
            self.next.set(start + layout.size());
            self.end.set(base + pages * PAGE);
            return start as *mut u8;
        }
        self.next.set(new_next);
        start as *mut u8
    }

    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump { next: Cell::new(0), end: Cell::new(0) };

/// `tog_v1_alloc(len) -> ptr`: memory for the host to write entry-point arguments into.
#[no_mangle]
pub extern "C" fn tog_v1_alloc(len: i32) -> i32 {
    let layout = Layout::from_size_align(len.max(1) as usize, 1).expect("valid layout");
    // SAFETY: non-zero size.
    let p = unsafe { ALLOC.alloc(layout) };
    if p.is_null() {
        // Out of memory: trap here rather than hand the host address 0 to write into (H-7).
        core::arch::wasm32::unreachable();
    }
    p as i32
}

/// A runtime reports the panic message to the host, then traps.
#[cfg(feature = "runtime")]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use alloc::string::ToString;
    let msg = info.to_string();
    crate::ffi::report_panic(msg.as_bytes());
    core::arch::wasm32::unreachable()
}

/// A verification blob imports nothing, so it just traps.
#[cfg(not(feature = "runtime"))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
