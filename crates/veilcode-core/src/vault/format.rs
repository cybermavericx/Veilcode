//! Vault file header (SPEC §7):
//! magic(8) | format u8 | m u32 LE | t u32 LE | p u32 LE | salt(16) | xnonce(24) | ct+tag.

use crate::error::{CoreError, Result};

pub(crate) const MAGIC: &[u8; 8] = b"VEILCODE";
pub(crate) const FORMAT: u8 = 1;
pub(crate) const SALT_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const M_AT: usize = 9;
pub(crate) const T_AT: usize = 13;
pub(crate) const P_AT: usize = 17;
pub(crate) const SALT_AT: usize = 21;
pub(crate) const NONCE_AT: usize = SALT_AT + SALT_LEN;
pub(crate) const HEADER_LEN: usize = NONCE_AT + NONCE_LEN;
const TAG_LEN: usize = 16;

/// Argon2id cost parameters as stored in the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KdfParams {
    pub(crate) m_cost: u32,
    pub(crate) t_cost: u32,
    pub(crate) p_cost: u32,
}

impl KdfParams {
    /// Production parameters (SPEC §7).
    pub(crate) const PRODUCTION: KdfParams = KdfParams {
        m_cost: 65536,
        t_cost: 3,
        p_cost: 1,
    };

    /// D6 bounds, checked before the KDF ever runs.
    pub(crate) fn check(&self) -> Result<()> {
        let ok = (8..=262_144).contains(&self.m_cost)
            && (1..=10).contains(&self.t_cost)
            && (1..=4).contains(&self.p_cost);
        if ok {
            Ok(())
        } else {
            Err(CoreError::VaultOpen)
        }
    }
}

/// Parsed header fields.
pub(crate) struct Header {
    pub(crate) params: KdfParams,
    pub(crate) salt: [u8; SALT_LEN],
    pub(crate) nonce: [u8; NONCE_LEN],
}

impl Header {
    /// Serialises the header; these bytes are also the AEAD AAD.
    pub(crate) fn to_bytes(&self) -> [u8; HEADER_LEN] {
        let mut out = [0u8; HEADER_LEN];
        out[..M_AT - 1].copy_from_slice(MAGIC);
        out[M_AT - 1] = FORMAT;
        out[M_AT..T_AT].copy_from_slice(&self.params.m_cost.to_le_bytes());
        out[T_AT..P_AT].copy_from_slice(&self.params.t_cost.to_le_bytes());
        out[P_AT..SALT_AT].copy_from_slice(&self.params.p_cost.to_le_bytes());
        out[SALT_AT..NONCE_AT].copy_from_slice(&self.salt);
        out[NONCE_AT..].copy_from_slice(&self.nonce);
        out
    }

    /// Splits a vault file into a bounds-checked header and the ciphertext.
    pub(crate) fn parse(file: &[u8]) -> Result<(Header, &[u8])> {
        if file.len() < HEADER_LEN + TAG_LEN || &file[..M_AT - 1] != MAGIC {
            return Err(CoreError::VaultOpen);
        }
        if file[M_AT - 1] != FORMAT {
            return Err(CoreError::VaultOpen);
        }
        let params = KdfParams {
            m_cost: le_u32(file, M_AT),
            t_cost: le_u32(file, T_AT),
            p_cost: le_u32(file, P_AT),
        };
        params.check()?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&file[SALT_AT..NONCE_AT]);
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&file[NONCE_AT..HEADER_LEN]);
        let header = Header {
            params,
            salt,
            nonce,
        };
        Ok((header, &file[HEADER_LEN..]))
    }
}

/// Reads a little-endian u32 at `at`; the caller has checked the length.
pub(crate) fn le_u32(bytes: &[u8], at: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&bytes[at..at + 4]);
    u32::from_le_bytes(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_layout_and_bounds() {
        let h = Header {
            params: KdfParams {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1,
            },
            salt: [7; SALT_LEN],
            nonce: [9; NONCE_LEN],
        };
        let b = h.to_bytes();
        assert_eq!(HEADER_LEN, 61);
        assert_eq!(&b[..8], b"VEILCODE");
        assert_eq!(b[8], 1);
        assert_eq!(le_u32(&b, M_AT), 8);
        assert_eq!(&b[SALT_AT..NONCE_AT], &[7; SALT_LEN]);
        let bad = KdfParams {
            m_cost: 262_145,
            t_cost: 1,
            p_cost: 1,
        };
        assert!(matches!(bad.check(), Err(CoreError::VaultOpen)));
        assert!(KdfParams::PRODUCTION.check().is_ok());
    }
}
