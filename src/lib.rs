#![cfg(target_os = "macos")]
#![allow(deprecated)]
// napi-rs expands exports into audited FFI glue that locally allows unsafe code.
// `deny` still rejects unsafe code written in this crate's source modules.
#![deny(unsafe_code)]
#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

pub mod api;
