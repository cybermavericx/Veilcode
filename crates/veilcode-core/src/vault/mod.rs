//! The encrypted vault file (SPEC §7).

mod crypto;
mod format;
mod model;
mod session;

pub use model::{Session, SessionId};
pub(crate) use session::{DEFAULT_TTL_DAYS, ttl_secs};
pub use session::{PurgeResult, VaultStatus};

use crate::clock::{Clock, SystemClock};
use crate::error::{CoreError, Result};
use crate::hex;
use crate::rng::{OsRandom, RandomSource};
use crate::scan::ScanOptions;
use crate::secret::{SecretBytes, SecretString};
use crate::token::{KnownPrefixes, Token, TokenGen, TokenPrefix};
use crypto::Key;
pub(crate) use format::KdfParams;
use format::{HEADER_LEN, Header, NONCE_LEN, SALT_LEN};
use model::{Entry, VaultData};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

/// D81: the default vault, `vault.vc` in the local (non-roaming) data dir
/// (`%LOCALAPPDATA%` on Windows). `None` if the OS reports no home directory.
pub fn default_vault_path() -> Option<PathBuf> {
    let dirs = directories::ProjectDirs::from("com", "Cybermavericx", "Veilcode")?;
    Some(dirs.data_local_dir().join("vault.vc"))
}

/// Minimum passphrase length in Unicode scalar values (D8).
const MIN_PASSPHRASE_CHARS: usize = 12;

/// An open, decrypted vault. Values never appear in `Debug`.
pub struct Vault {
    path: PathBuf,
    params: KdfParams,
    salt: [u8; SALT_LEN],
    key: Key,
    data: VaultData,
    /// sha256 of the file as last read or written; `None` if not yet saved (D7).
    file_hash: Option<[u8; 32]>,
    /// Expired sessions purged by the open that produced this value (D61).
    expired_removed: usize,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("sessions", &self.data.sessions.len())
            .field("entries", &self.data.entries.len())
            .finish_non_exhaustive()
    }
}

impl Vault {
    /// A new, empty vault at `path` (written on the first `save`).
    pub fn create(path: &Path, pass: &SecretString) -> Result<Vault> {
        Vault::create_with_params(path, pass, KdfParams::PRODUCTION)
    }

    /// `create` with explicit KDF params (tests use low params).
    pub(crate) fn create_with_params(
        path: &Path,
        pass: &SecretString,
        params: KdfParams,
    ) -> Result<Vault> {
        if pass.expose().chars().count() < MIN_PASSPHRASE_CHARS {
            return Err(CoreError::PassphraseTooShort);
        }
        let mut salt = [0u8; SALT_LEN];
        OsRandom.fill(&mut salt)?;
        let key = crypto::derive_key(&params, pass, &salt)?;
        Ok(Vault {
            path: path.to_path_buf(),
            params,
            salt,
            key,
            data: VaultData::default(),
            file_hash: None,
            expired_removed: 0,
        })
    }

    /// Opens and decrypts the vault at `path`, then purges expired
    /// sessions by the system clock (D61; see `expired_removed`).
    pub fn open(path: &Path, pass: &SecretString) -> Result<Vault> {
        Vault::open_with_clock(path, pass, &SystemClock)
    }

    /// `open` with an injected clock. If any session expired
    /// (`expires_at <= now`), the vault is saved (or removed, D62) at once.
    /// Crate-internal (D70): no production clock override.
    pub(crate) fn open_with_clock(
        path: &Path,
        pass: &SecretString,
        clock: &dyn Clock,
    ) -> Result<Vault> {
        let mut vault = Vault::decrypt(path, pass)?;
        vault.expired_removed = vault.purge_expired(clock.now_unix())?;
        Ok(vault)
    }

    fn decrypt(path: &Path, pass: &SecretString) -> Result<Vault> {
        let file = std::fs::read(path).map_err(|e| CoreError::io(path, &e))?;
        let (header, ciphertext) = Header::parse(&file)?;
        let key = crypto::derive_key(&header.params, pass, &header.salt)?;
        let aad = &file[..HEADER_LEN];
        let plain = crypto::open(&key, &header.nonce, aad, ciphertext)?;
        let data = VaultData::from_json(&plain)?;
        Ok(Vault {
            path: path.to_path_buf(),
            params: header.params,
            salt: header.salt,
            key,
            data,
            file_hash: Some(sha256(&file)),
            expired_removed: 0,
        })
    }

    /// Encrypts with a fresh nonce and atomically replaces the file.
    /// Creating `vault.vc.tmp` exclusively is the writer lock (D28).
    pub fn save(&mut self) -> Result<()> {
        let tmp = self.tmp_path();
        let lock = create_tmp(&tmp)?;
        let result = self.save_locked(lock, &tmp);
        if result.is_err() {
            // We created the tmp file, so it is ours to remove (ciphertext at most).
            let _ = std::fs::remove_file(&tmp);
        }
        result
    }

    /// D7 check, write, fsync, rename and directory fsync, under the lock.
    fn save_locked(&mut self, mut tmp_file: File, tmp: &Path) -> Result<()> {
        self.check_unchanged()?;
        let file = self.encrypt()?;
        tmp_file
            .write_all(&file)
            .and_then(|()| tmp_file.sync_all())
            .map_err(|e| CoreError::io(tmp, &e))?;
        drop(tmp_file);
        std::fs::rename(tmp, &self.path).map_err(|e| CoreError::io(&self.path, &e))?;
        self.file_hash = Some(sha256(&file));
        sync_parent_dir(&self.path)
    }

    fn tmp_path(&self) -> PathBuf {
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        PathBuf::from(tmp)
    }

    /// Header (fresh nonce) followed by the sealed JSON.
    fn encrypt(&self) -> Result<Vec<u8>> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRandom.fill(&mut nonce)?;
        let header = Header {
            params: self.params,
            salt: self.salt,
            nonce,
        }
        .to_bytes();
        let plain = self.data.to_json()?;
        let ciphertext = crypto::seal(&self.key, &nonce, &header, &plain)?;
        Ok([header.as_slice(), &ciphertext].concat())
    }

    /// D7: refuse to save if the file on disk is not the one we last saw.
    fn check_unchanged(&self) -> Result<()> {
        let on_disk = match std::fs::read(&self.path) {
            Ok(bytes) => Some(sha256(&bytes)),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => return Err(CoreError::io(&self.path, &e)),
        };
        if on_disk == self.file_hash {
            Ok(())
        } else {
            Err(CoreError::VaultChanged)
        }
    }

    /// The default-prefix token for `value` (see `get_or_create_token_with`).
    pub fn get_or_create_token(
        &mut self,
        value: &SecretBytes,
        name: &str,
        rule_id: &str,
        input_haystacks: &[&[u8]],
    ) -> Result<Token> {
        let prefix = TokenPrefix::default();
        self.get_or_create_token_with(value, name, rule_id, &prefix, input_haystacks)
    }

    /// The `prefix` token for `value`, creating an entry if this value has
    /// no token with this prefix yet (dedupe per value and prefix, D138).
    /// NAME comes from `name`, or from `rule_id` when `name` is empty (SPEC §4).
    pub fn get_or_create_token_with(
        &mut self,
        value: &SecretBytes,
        name: &str,
        rule_id: &str,
        prefix: &TokenPrefix,
        input_haystacks: &[&[u8]],
    ) -> Result<Token> {
        if value.is_empty() {
            return Err(CoreError::EmptyValue);
        }
        let same = |e: &Entry| e.value == *value && e.prefix == *prefix;
        if let Some((token, _)) = self.data.entries.iter().find(|(_, e)| same(e)) {
            return Ok(token.clone());
        }
        let base = if name.is_empty() { rule_id } else { name };
        let entries = &self.data.entries;
        let exists = |t: &Token| entries.contains_key(t);
        let token = TokenGen::new(OsRandom).generate(base, prefix, exists, input_haystacks)?;
        let entry = Entry {
            value: value.clone(),
            name: name.to_string(),
            rule_id: rule_id.to_string(),
            prefix: prefix.clone(),
        };
        self.data.entries.insert(token.clone(), entry);
        Ok(token)
    }

    /// The prefixes of every entry, plus the default (D138).
    pub(crate) fn known_prefixes(&self) -> KnownPrefixes {
        KnownPrefixes::new(self.data.entries.values().map(|e| &e.prefix))
    }

    /// Test shorthand: an entry with exactly `token` (R15b).
    #[cfg(test)]
    pub(crate) fn insert_test_entry(
        &mut self,
        token: &str,
        prefix: &TokenPrefix,
        value: SecretBytes,
    ) -> Token {
        let t = Token::parse_with(token, prefix).expect("token of its prefix");
        let entry = Entry {
            value,
            name: "k".to_string(),
            rule_id: "r".to_string(),
            prefix: prefix.clone(),
        };
        self.data.entries.insert(t.clone(), entry);
        t
    }

    /// The plaintext JSON the next save would encrypt (R15).
    #[cfg(test)]
    pub(crate) fn plaintext_json(&self) -> zeroize::Zeroizing<Vec<u8>> {
        self.data.to_json().expect("json")
    }

    /// The secret for `token`. Crate-internal: only restore reads values.
    pub(crate) fn value(&self, token: &Token) -> Option<&SecretBytes> {
        self.data.entries.get(token).map(|e| &e.value)
    }

    /// Records a new session (D24 id, `created` now, D61 `expires_at`).
    pub(crate) fn add_session(
        &mut self,
        source_label: &str,
        tokens: Vec<Token>,
        ttl_days: u32,
        scan_options: ScanOptions,
    ) -> Result<SessionId> {
        let ttl = session::ttl_secs(ttl_days)?;
        let mut raw = [0u8; 8];
        OsRandom.fill(&mut raw)?;
        let id = SessionId(hex::encode(&raw));
        let created = SystemClock.now_unix();
        self.data.sessions.push(Session {
            id: id.clone(),
            created,
            expires_at: created.saturating_add(ttl),
            source_label: source_label.to_string(),
            scan_options,
            tokens,
        });
        Ok(id)
    }

    /// Test shorthand: a session with the default TTL and walk options.
    #[cfg(test)]
    pub(crate) fn add_test_session(
        &mut self,
        label: &str,
        tokens: Vec<Token>,
    ) -> Result<SessionId> {
        self.add_session(
            label,
            tokens,
            session::DEFAULT_TTL_DAYS,
            ScanOptions::default(),
        )
    }

    /// All sessions, oldest first.
    pub fn sessions(&self) -> &[Session] {
        &self.data.sessions
    }

    /// A copy of the decrypted state (mask rolls back to it on failure).
    pub(crate) fn snapshot(&self) -> Snapshot {
        Snapshot(self.data.clone())
    }

    /// Puts back a `snapshot` (memory only).
    pub(crate) fn restore_snapshot(&mut self, snapshot: Snapshot) {
        self.data = snapshot.0;
    }

    /// Sessions removed as expired by the open that produced this vault (D61).
    pub fn expired_removed(&self) -> usize {
        self.expired_removed
    }
}

/// An in-memory copy of the vault contents (values wiped on drop).
pub(crate) struct Snapshot(VaultData);

/// Creates the tmp file exclusively (never follows or overwrites one), 0600 on Unix.
fn create_tmp(tmp: &Path) -> Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(tmp).map_err(|e| match e.kind() {
        ErrorKind::AlreadyExists => CoreError::SaveLocked,
        _ => CoreError::io(tmp, &e),
    })
}

/// Makes the rename durable: fsync the parent directory (Unix only).
#[cfg(unix)]
fn sync_parent_dir(path: &Path) -> Result<()> {
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    File::open(parent)
        .and_then(|d| d.sync_all())
        .map_err(|e| CoreError::io(parent, &e))
}

#[cfg(not(unix))]
fn sync_parent_dir(_path: &Path) -> Result<()> {
    Ok(())
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::format::{HEADER_LEN, M_AT, NONCE_AT, P_AT, T_AT, le_u32};
    use super::*;
    use crate::test_support::*;
    use std::time::{Duration, Instant};

    const GENERIC: &str = "wrong passphrase or corrupted vault";

    fn secret(s: &str) -> SecretBytes {
        SecretBytes::new(s.as_bytes().to_vec())
    }

    fn saved_small_vault(dir: &Path) -> (PathBuf, String) {
        let mut v = test_vault(dir);
        let value = fake_password();
        v.get_or_create_token(&secret(&value), "k", "rule", &[])
            .expect("token");
        v.save().expect("save");
        (dir.join("vault.vc"), value)
    }

    #[test]
    fn v1_create_save_open_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let values = [
            secret(&fake_github_pat()),
            secret(&fake_password()),
            SecretBytes::new([b"p\xc3\xa4ss-".as_slice(), random_alnum(12).as_bytes()].concat()),
        ];
        let mut toks = Vec::new();
        for (i, val) in values.iter().enumerate() {
            let t = v.get_or_create_token(val, &format!("key{i}"), "rule", &[]);
            toks.push(t.expect("token"));
        }
        v.add_test_session("first", toks[..2].to_vec())
            .expect("session");
        v.add_test_session("second", toks[2..].to_vec())
            .expect("session");
        v.save().expect("save");
        let r = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("open");
        assert_eq!(r.data.entries.len(), 3);
        assert_eq!(r.sessions().len(), 2);
        assert!(r.data.entries == v.data.entries);
        assert_eq!(r.sessions(), v.sessions());
        assert_eq!(r.sessions()[1].source_label, "second");
        assert_eq!(r.sessions()[0].id.as_str().len(), 16);
    }

    #[test]
    fn v2_wrong_passphrase_is_generic_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, value) = saved_small_vault(dir.path());
        let wrong = fake_password();
        let err = Vault::open(&path, &SecretString::new(wrong.clone())).expect_err("must fail");
        assert_eq!(err.to_string(), GENERIC);
        assert!(matches!(err, CoreError::VaultOpen));
        let out = format!("{err} {err:?}");
        assert_no_secret(out.as_bytes(), &[value, wrong]);
    }

    #[test]
    fn v3_single_bit_flip_at_every_offset_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, value) = saved_small_vault(dir.path());
        let good = std::fs::read(&path).expect("read");
        assert!(good.len() > HEADER_LEN + 16);
        for at in 0..good.len() {
            for bit in 0..8 {
                let mut bad = good.clone();
                bad[at] ^= 1 << bit;
                std::fs::write(&path, &bad).expect("write");
                let err = Vault::open(&path, &test_pass()).expect_err("tamper must fail");
                assert_eq!(err.to_string(), GENERIC, "offset {at} bit {bit}");
                assert_no_secret(format!("{err:?}").as_bytes(), &[&value]);
            }
        }
        std::fs::write(&path, &good).expect("write");
        assert!(Vault::open(&path, &test_pass()).is_ok());
    }

    #[test]
    fn v4_fresh_nonce_per_save() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let first = std::fs::read(&path).expect("read");
        let mut v = Vault::open(&path, &test_pass()).expect("open");
        v.save().expect("save");
        let second = std::fs::read(&path).expect("read");
        assert_eq!(first.len(), second.len());
        assert_eq!(first[..NONCE_AT], second[..NONCE_AT]);
        assert_ne!(first[NONCE_AT..HEADER_LEN], second[NONCE_AT..HEADER_LEN]);
        assert_ne!(first[HEADER_LEN..], second[HEADER_LEN..]);
    }

    #[test]
    fn v5_atomic_save_leaves_no_temp_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        assert!(!dir.path().join("vault.vc.tmp").exists());
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(&bytes[..8], b"VEILCODE");
    }

    #[test]
    fn v6_kdf_params_come_from_the_header() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let bytes = std::fs::read(&path).expect("read");
        assert_eq!(bytes[8], 1);
        assert_eq!(le_u32(&bytes, M_AT), 8);
        assert_eq!(le_u32(&bytes, T_AT), 1);
        assert_eq!(le_u32(&bytes, P_AT), 1);
        let v = Vault::open(&path, &test_pass()).expect("open");
        assert_eq!(
            v.params,
            KdfParams {
                m_cost: 8,
                t_cost: 1,
                p_cost: 1
            }
        );
        assert_eq!(v.data.entries.len(), 1);
    }

    #[test]
    fn v7_minimum_passphrase_length() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("vault.vc");
        let short = [random_alnum(11), "é".repeat(11)];
        for s in short {
            let err = Vault::create(&path, &SecretString::new(s.clone())).expect_err("too short");
            assert!(matches!(err, CoreError::PassphraseTooShort));
            assert_no_secret(format!("{err} {err:?}").as_bytes(), &[&s]);
        }
        assert_eq!("é".repeat(11).len(), 22);
        assert!(Vault::create(&path, &SecretString::new(random_alnum(12))).is_ok());
        let v = Vault::create(&path, &SecretString::new("é".repeat(12))).expect("12 chars");
        assert_eq!(v.params, KdfParams::PRODUCTION);
    }

    #[test]
    fn v8_debug_never_prints_secrets() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pass = fake_password();
        let path = dir.path().join("vault.vc");
        let low = KdfParams {
            m_cost: 8,
            t_cost: 1,
            p_cost: 1,
        };
        let mut v = Vault::create_with_params(&path, &SecretString::new(pass.clone()), low)
            .expect("create");
        let value = fake_github_pat();
        let t = v.get_or_create_token(&secret(&value), "token", "github-pat", &[]);
        let t = t.expect("token");
        let entry = v.data.entries.get(&t).expect("entry");
        let out = format!("{v:?} {entry:?} {:?}", v.value(&t));
        assert!(out.contains("SecretBytes(<redacted>, len=40)"), "{out}");
        assert_no_secret(out.as_bytes(), &[&value, &pass]);
    }

    fn patch_u32(path: &Path, at: usize, val: u32) {
        let mut bytes = std::fs::read(path).expect("read");
        bytes[at..at + 4].copy_from_slice(&val.to_le_bytes());
        std::fs::write(path, bytes).expect("write");
    }

    #[test]
    fn v9_absurd_header_params_rejected_before_kdf() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, value) = saved_small_vault(dir.path());
        let good = std::fs::read(&path).expect("read");
        for (at, val) in [(M_AT, u32::MAX), (T_AT, 0), (P_AT, 5)] {
            std::fs::write(&path, &good).expect("write");
            patch_u32(&path, at, val);
            let before = crypto::kdf_calls();
            let start = Instant::now();
            let err = Vault::open(&path, &test_pass()).expect_err("must fail");
            assert!(start.elapsed() < Duration::from_secs(1));
            assert_eq!(crypto::kdf_calls(), before, "KDF ran for offset {at}");
            assert_eq!(err.to_string(), GENERIC);
            assert_no_secret(format!("{err:?}").as_bytes(), &[&value]);
        }
        std::fs::write(&path, &good).expect("write");
        let before = crypto::kdf_calls();
        Vault::open(&path, &test_pass()).expect("open");
        assert_eq!(crypto::kdf_calls(), before + 1);
    }

    #[test]
    fn v10_non_utf8_value_roundtrip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let raw = SecretBytes::new(vec![0xff, 0xfe, b'a']);
        let t = v
            .get_or_create_token(&raw, "bin", "rule", &[])
            .expect("token");
        v.save().expect("save");
        let r = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("open");
        let got = r.value(&t).expect("value");
        assert_eq!(got.expose(), &[0xff, 0xfe, b'a']);
    }

    #[test]
    fn v11_concurrent_writer_detection() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let mut a = Vault::open(&path, &test_pass()).expect("open a");
        let mut b = Vault::open(&path, &test_pass()).expect("open b");
        b.add_test_session("from b", Vec::new()).expect("session");
        b.save().expect("save b");
        let after_b = std::fs::read(&path).expect("read");
        a.add_test_session("from a", Vec::new()).expect("session");
        let err = a.save().expect_err("a must be refused");
        assert!(matches!(err, CoreError::VaultChanged));
        assert_eq!(
            err.to_string(),
            "vault changed by another Veilcode process — reopen"
        );
        assert_eq!(std::fs::read(&path).expect("read"), after_b);
        let r = Vault::open(&path, &test_pass()).expect("open");
        assert_eq!(r.sessions()[0].source_label, "from b");
    }

    #[test]
    fn new_vault_save_refuses_to_overwrite_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let before = std::fs::read(&path).expect("read");
        let mut fresh = test_vault(dir.path());
        assert!(matches!(fresh.save(), Err(CoreError::VaultChanged)));
        assert_eq!(std::fs::read(&path).expect("read"), before);
    }

    #[test]
    fn t2_ten_thousand_tokens_are_distinct() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let mut seen = std::collections::BTreeSet::new();
        for i in 0..10_000u32 {
            let val = SecretBytes::new(i.to_le_bytes().to_vec());
            seen.insert(
                v.get_or_create_token(&val, "k", "rule", &[])
                    .expect("token"),
            );
        }
        assert_eq!(seen.len(), 10_000);
        assert_eq!(v.data.entries.len(), 10_000);
    }

    #[test]
    fn t10_two_prefixes_save_and_open_with_values() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let custom = TokenPrefix::parse("Infra_Mask_").expect("prefix");
        let (a, b) = (fake_password(), fake_password());
        let ta = v
            .get_or_create_token(&secret(&a), "db", "r", &[])
            .expect("token");
        let tb = v
            .get_or_create_token_with(&secret(&b), "db", "r", &custom, &[])
            .expect("token");
        assert!(ta.as_str().starts_with("VEILCODE_DB_"));
        assert!(tb.as_str().starts_with("Infra_Mask_DB_"));
        v.add_test_session("s", vec![ta.clone(), tb.clone()])
            .expect("session");
        v.save().expect("save");
        let r = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("open");
        assert_eq!(r.value(&ta).map(|s| s.expose()), Some(a.as_bytes()));
        assert_eq!(r.value(&tb).map(|s| s.expose()), Some(b.as_bytes()));
        assert_eq!(r.data.entries[&ta].prefix, TokenPrefix::default());
        assert_eq!(r.data.entries[&tb].prefix, custom);
        let known: Vec<String> = r
            .known_prefixes()
            .list()
            .iter()
            .map(|p| p.as_str().to_string())
            .collect();
        assert_eq!(known, vec!["Infra_Mask_", "VEILCODE_"]);
    }

    #[test]
    fn t10_dedupe_is_per_prefix() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let custom = TokenPrefix::parse("Infra_Mask_").expect("prefix");
        let val = secret(&fake_password());
        let d1 = v.get_or_create_token(&val, "k", "r", &[]).expect("token");
        let c1 = v
            .get_or_create_token_with(&val, "k", "r", &custom, &[])
            .expect("token");
        let c2 = v
            .get_or_create_token_with(&val, "other", "r", &custom, &[])
            .expect("token");
        let d2 = v.get_or_create_token(&val, "x", "r", &[]).expect("token");
        assert_eq!((c1.clone(), d1.clone()), (c2, d2));
        assert_ne!(c1, d1);
        assert!(c1.as_str().starts_with("Infra_Mask_K_"));
        assert_eq!(v.data.entries.len(), 2);
    }

    #[test]
    fn t3_dedupe_returns_same_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let val = secret(&fake_password());
        let a = v
            .get_or_create_token(&val, "first", "r1", &[])
            .expect("token");
        let b = v
            .get_or_create_token(&val, "second", "r2", &[])
            .expect("token");
        assert_eq!(a, b);
        assert_eq!(v.data.entries.len(), 1);
        assert!(a.as_str().starts_with("VEILCODE_FIRST_"));
    }

    #[test]
    fn empty_name_uses_rule_id() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let t = v.get_or_create_token(&secret(&fake_password()), "", "github-pat", &[]);
        assert!(
            t.expect("token")
                .as_str()
                .starts_with("VEILCODE_GITHUB_PAT_")
        );
    }

    #[test]
    fn t8_empty_secret_rejected() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let err = v
            .get_or_create_token(&SecretBytes::new(Vec::new()), "k", "rule", &[])
            .expect_err("empty value");
        assert!(matches!(err, CoreError::EmptyValue));
        assert_eq!(err.to_string(), "secret value is empty");
        assert!(v.data.entries.is_empty());
    }

    #[test]
    fn v12_malformed_files_never_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let good = std::fs::read(&path).expect("read");
        let shapes: [&[u8]; 4] = [
            &[],
            &good[..8],
            &good[..HEADER_LEN],
            &good[..HEADER_LEN + 15],
        ];
        for shape in shapes {
            std::fs::write(&path, shape).expect("write");
            let err = Vault::open(&path, &test_pass()).expect_err("malformed");
            assert_eq!(err.to_string(), GENERIC, "len {}", shape.len());
        }
        let err = Vault::open(dir.path(), &test_pass()).expect_err("directory");
        match err {
            CoreError::Io { path, .. } => assert_eq!(path, dir.path()),
            other => panic!("expected Io, got {other}"),
        }
    }

    #[test]
    fn v13_save_lock_and_file_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let tmp = dir.path().join("vault.vc.tmp");
        let vault_before = std::fs::read(&path).expect("read");
        std::fs::write(&tmp, b"stale").expect("write tmp");
        let mut v = Vault::open(&path, &test_pass()).expect("open");
        let err = v.save().expect_err("locked");
        assert!(matches!(err, CoreError::SaveLocked));
        assert_eq!(
            err.to_string(),
            "vault is being saved by another Veilcode process, or a previous save crashed \
             — delete vault.vc.tmp if no Veilcode is running"
        );
        assert_eq!(std::fs::read(&path).expect("read"), vault_before);
        assert_eq!(std::fs::read(&tmp).expect("read tmp"), b"stale");
        std::fs::remove_file(&tmp).expect("remove tmp");
        v.save().expect("save after unlock");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn failed_save_releases_the_lock() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (path, _) = saved_small_vault(dir.path());
        let mut a = Vault::open(&path, &test_pass()).expect("open a");
        let mut b = Vault::open(&path, &test_pass()).expect("open b");
        b.save().expect("save b");
        assert!(matches!(a.save(), Err(CoreError::VaultChanged)));
        assert!(!dir.path().join("vault.vc.tmp").exists());
    }

    #[test]
    fn se1_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut v = test_vault(dir.path());
        let (shared, a, b) = (fake_password(), fake_password(), fake_password());
        let mut tok = |s: &str| {
            v.get_or_create_token(&secret(s), "k", "rule", &[])
                .expect("token")
        };
        let (ts, ta, tb) = (tok(&shared), tok(&a), tok(&b));
        let one = v
            .add_test_session("one", vec![ts.clone(), ta.clone()])
            .expect("s1");
        v.add_test_session("two", vec![ts.clone(), tb.clone(), ts.clone()])
            .expect("s2");
        let counts: Vec<_> = v
            .sessions()
            .iter()
            .map(|s| (s.source_label.as_str(), s.tokens.len()))
            .collect();
        assert_eq!(counts, vec![("one", 2), ("two", 3)]);
        v.delete_session(&one).expect("delete");
        assert!(
            v.value(&ts)
                .is_some_and(|x| x.expose() == shared.as_bytes())
        );
        assert!(v.value(&ta).is_none());
        assert!(v.value(&tb).is_some());
        assert_eq!(v.data.entries.len(), 2);
        let labels: Vec<_> = v
            .sessions()
            .iter()
            .map(|s| s.source_label.as_str())
            .collect();
        assert_eq!(labels, vec!["two"]);
        let err = v.delete_session(&one).expect_err("unknown id");
        assert!(matches!(err, CoreError::UnknownSession { ref id } if id == one.as_str()));
        assert_eq!(err.to_string(), format!("unknown session {}", one.as_str()));
        v.save().expect("save");
        let r = Vault::open(&dir.path().join("vault.vc"), &test_pass()).expect("open");
        assert_eq!((r.sessions().len(), r.data.entries.len()), (1, 2));
        assert_no_secret(
            format!("{err:?} {:?}", r.sessions()).as_bytes(),
            &[&shared, &a, &b],
        );
    }
}
