//! Argon2id key derivation and XChaCha20-Poly1305 sealing (SPEC §7).

use super::format::{KdfParams, NONCE_LEN, SALT_LEN};
use crate::error::{CoreError, Result};
use crate::secret::SecretString;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

/// The 32-byte vault key, wiped on drop.
pub(crate) type Key = Zeroizing<[u8; 32]>;

#[cfg(test)]
thread_local! {
    static KDF_CALLS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Number of KDF calls made on this thread (V9).
#[cfg(test)]
pub(crate) fn kdf_calls() -> u32 {
    KDF_CALLS.with(|c| c.get())
}

/// Argon2id(pass, salt) with `params`. Any failure is the generic open error.
pub(crate) fn derive_key(
    params: &KdfParams,
    pass: &SecretString,
    salt: &[u8; SALT_LEN],
) -> Result<Key> {
    #[cfg(test)]
    KDF_CALLS.with(|c| c.set(c.get() + 1));
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| CoreError::VaultOpen)?;
    // D27: caller-owned KDF memory, wiped on drop (Block: Zeroize via argon2's feature).
    let mut blocks = Zeroizing::new(vec![Block::new(); p.block_count()]);
    let mut key: Key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into_with_memory(
            pass.expose().as_bytes(),
            salt,
            &mut key[..],
            &mut blocks[..],
        )
        .map_err(|_| CoreError::VaultOpen)?;
    Ok(key)
}

fn cipher(key: &Key) -> Result<XChaCha20Poly1305> {
    XChaCha20Poly1305::new_from_slice(&key[..]).map_err(|_| CoreError::Encrypt)
}

/// Encrypts `plaintext`; returns ciphertext with the tag appended.
pub(crate) fn seal(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    cipher(key)?
        .encrypt(&XNonce::from(*nonce), payload)
        .map_err(|_| CoreError::Encrypt)
}

/// Decrypts and authenticates; any failure is the generic open error.
pub(crate) fn open(
    key: &Key,
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let payload = Payload {
        msg: ciphertext,
        aad,
    };
    let c = cipher(key).map_err(|_| CoreError::VaultOpen)?;
    c.decrypt(&XNonce::from(*nonce), payload)
        .map(Zeroizing::new)
        .map_err(|_| CoreError::VaultOpen)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_matches_argon2_reference() {
        let params = KdfParams {
            m_cost: 64,
            t_cost: 2,
            p_cost: 2,
        };
        let pass = SecretString::new("reference passphrase".into());
        let salt = [5u8; SALT_LEN];
        let key = derive_key(&params, &pass, &salt).expect("derive");
        let p = Params::new(64, 2, 2, Some(32)).expect("params");
        let mut expect = [0u8; 32];
        Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
            .hash_password_into(b"reference passphrase", &salt, &mut expect)
            .expect("reference");
        assert_eq!(*key, expect);
    }
}
