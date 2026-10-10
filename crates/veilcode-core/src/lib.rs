//! Veilcode core: all masking, restore, scanning and vault logic lives here.
//!
//! This crate does no printing, no prompting and no process launching.
#![forbid(unsafe_code)]

mod error;
mod hex;
mod rng;
mod secret;
mod token;
mod vault;

#[cfg(test)]
mod test_support;

pub use error::{CoreError, Result};
pub use secret::{SecretBytes, SecretString};
pub use token::{TOKEN_PATTERN, Token};
pub use vault::{Session, SessionId, Vault};
