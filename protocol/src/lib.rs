//! Shared wire formats for agent-sudo.
//!
//! - [`wire`]: the line codec spoken on the root-only socket between the setuid
//!   `agent-sudo` binary and `agent-sudo-hostd` (mirrors `sudo/src/sudo/agent/wire.rs`).
//! - [`api`]: JSON bodies exchanged between hostd and the approval service.
//! - [`signing`]: Ed25519 request signatures that authenticate a host to the service.

pub mod api;
pub mod local;
pub mod signing;
pub mod wire;

/// Version of the host <-> service protocol.
pub const PROTOCOL_VERSION: u32 = 1;
