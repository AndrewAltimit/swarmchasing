//! The CLI's integration tests as one test binary.
//!
//! Each `tests/<name>.rs` is a module here rather than its own binary
//! (`autotests = false` in Cargo.toml): one compile and one link instead of
//! one per file. They run the built `swarmchase` in a scratch data directory
//! over `samples/eval/`, and never touch the network. Run a single file's
//! tests with `cargo test -p swarmchase --test integration <name>::`.

mod analysis;
mod cases;
mod common;
mod eval;
mod exports;
mod notices;
mod watch;
mod workflow;
