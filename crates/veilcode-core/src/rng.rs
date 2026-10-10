//! Injectable randomness: the OS generator in production, scripted bytes in tests.

use crate::error::{CoreError, Result};

/// A source of random bytes.
pub(crate) trait RandomSource {
    /// Fills `buf` completely or fails.
    fn fill(&mut self, buf: &mut [u8]) -> Result<()>;
}

/// The operating system's generator (`getrandom`).
pub(crate) struct OsRandom;

impl RandomSource for OsRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        getrandom::fill(buf).map_err(|_| CoreError::Random)
    }
}

/// Test generator returning scripted bytes, then failing when they run out.
#[cfg(test)]
pub(crate) struct SeqRandom {
    bytes: Vec<u8>,
    pos: usize,
}

#[cfg(test)]
impl SeqRandom {
    pub(crate) fn new(bytes: &[u8]) -> Self {
        SeqRandom {
            bytes: bytes.to_vec(),
            pos: 0,
        }
    }
}

#[cfg(test)]
impl RandomSource for SeqRandom {
    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        let end = self.pos + buf.len();
        let src = self.bytes.get(self.pos..end).ok_or(CoreError::Random)?;
        buf.copy_from_slice(src);
        self.pos = end;
        Ok(())
    }
}
