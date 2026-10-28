//! Logging (§3.2). Collators and tests see the lines; validators discard them.

use crate::ffi;

/// Write one log line.
pub fn log(line: &str) {
    ffi::log_line(line.as_bytes())
}
