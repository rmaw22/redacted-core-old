//! redacted-core: the pure secret-detection engine.
//!
//! Everything here is free of filesystem, environment, network, time and thread
//! access, so it compiles to wasm32 and is reused by both the CLI hook and the
//! browser extension. Reading config from disk lives in the `redacted-cli` crate.

pub mod config;
pub mod scrub;

// Decoy-secret generators used only by tests. Core's own tests see it under
// `cfg(test)`; downstream crates enable the `test-support` feature to reuse it.
#[cfg(any(test, feature = "test-support"))]
pub mod fake_secrets;
