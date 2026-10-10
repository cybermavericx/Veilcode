//! Vault plaintext model and its JSON form (SPEC §7, D5).

use crate::error::{CoreError, Result};
use crate::hex;
use crate::secret::SecretBytes;
use crate::token::Token;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const VERSION: u32 = 1;

/// A session id: 16 lowercase hex characters (D24).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct SessionId(pub(crate) String);

impl TryFrom<String> for SessionId {
    type Error = &'static str;

    /// Accepts exactly 16 lowercase hex characters (D24).
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        let ok = s.len() == 16 && s.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(SessionId(s))
        } else {
            Err("invalid session id")
        }
    }
}

impl SessionId {
    /// The id text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One mask run (SPEC §6.4). Holds no secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: SessionId,
    /// Unix seconds.
    pub created: u64,
    pub source_label: String,
    pub tokens: Vec<Token>,
}

/// One vault entry: the secret value and where its token name came from.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) value: SecretBytes,
    pub(crate) name: String,
    pub(crate) rule_id: String,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("value", &self.value)
            .field("name", &self.name)
            .field("rule_id", &self.rule_id)
            .finish()
    }
}

/// Decrypted vault contents.
#[derive(Default)]
pub(crate) struct VaultData {
    pub(crate) sessions: Vec<Session>,
    pub(crate) entries: BTreeMap<Token, Entry>,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    version: u32,
    sessions: Vec<Session>,
    entries: BTreeMap<String, WireEntry>,
}

/// JSON form of an entry; the hex value is wiped on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct WireEntry {
    value_hex: String,
    name: String,
    rule_id: String,
}

impl VaultData {
    /// Serialises to JSON in a buffer that is wiped on drop.
    pub(crate) fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let entries = self
            .entries
            .iter()
            .map(|(t, e)| (t.as_str().to_string(), WireEntry::from(e)))
            .collect();
        let wire = Wire {
            version: VERSION,
            sessions: self.sessions.clone(),
            entries,
        };
        let mut buf = Zeroizing::new(Vec::with_capacity(json_capacity(&wire)));
        serde_json::to_writer(&mut *buf, &wire).map_err(|_| CoreError::Encrypt)?;
        Ok(buf)
    }

    /// Parses decrypted JSON; any problem is the generic open error.
    pub(crate) fn from_json(json: &[u8]) -> Result<VaultData> {
        let wire: Wire = serde_json::from_slice(json).map_err(|_| CoreError::VaultOpen)?;
        if wire.version != VERSION {
            return Err(CoreError::VaultOpen);
        }
        let mut entries = BTreeMap::new();
        for (t, w) in &wire.entries {
            let token = Token::parse(t).ok_or(CoreError::VaultOpen)?;
            let mut value = hex::decode(&w.value_hex).ok_or(CoreError::VaultOpen)?;
            let entry = Entry {
                // Moves the buffer out (no copy); the emptied wrapper drops.
                value: SecretBytes::new(std::mem::take(&mut *value)),
                name: w.name.clone(),
                rule_id: w.rule_id.clone(),
            };
            entries.insert(token, entry);
        }
        Ok(VaultData {
            sessions: wire.sessions.clone(),
            entries,
        })
    }
}

impl From<&Entry> for WireEntry {
    fn from(e: &Entry) -> Self {
        WireEntry {
            value_hex: hex::encode(e.value.expose()),
            name: e.name.clone(),
            rule_id: e.rule_id.clone(),
        }
    }
}

/// A generous size estimate so the buffer rarely reallocates (fewer stray copies).
fn json_capacity(wire: &Wire) -> usize {
    let entries: usize = wire
        .entries
        .iter()
        .map(|(t, e)| t.len() + e.value_hex.len() + (e.name.len() + e.rule_id.len()) * 6 + 64)
        .sum();
    let sessions: usize = wire
        .sessions
        .iter()
        .map(|s| s.source_label.len() * 6 + s.tokens.len() * 48 + 96)
        .sum();
    entries + sessions + 64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(token: &str, session_id: &str) -> Vec<u8> {
        format!(
            r#"{{"version":1,"sessions":[{{"id":"{session_id}","created":1,"source_label":"s","tokens":["{token}"]}}],"entries":{{}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn from_json_validates_session_ids_and_tokens() {
        let good_tok = "VEILCODE_K_ab000000";
        let good_id = "0123456789abcdef";
        let data = VaultData::from_json(&json(good_tok, good_id)).expect("valid");
        assert_eq!(data.sessions[0].tokens[0].as_str(), good_tok);
        for (tok, id) in [
            ("not-a-token", good_id),
            ("VEILCODE_K_ab0000001", good_id),
            (good_tok, "0123456789ABCDEF"),
            (good_tok, "0123456789abcde"),
        ] {
            let err = VaultData::from_json(&json(tok, id)).err();
            assert!(matches!(err, Some(CoreError::VaultOpen)), "{tok} {id}");
        }
    }
}
