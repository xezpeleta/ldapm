//! Core library for ldapm: profiles, TLS, tunnel, sessions and directory reads.
//!
//! Front-ends (the `ldapm` CLI) only parse input, call into this crate and
//! render results. No LDAP logic lives outside it.

pub mod conventions;
pub mod error;
pub mod profiles;
pub mod secret;
pub mod session;
pub mod tls;
pub mod tunnel;

pub use error::{Error, Result};
