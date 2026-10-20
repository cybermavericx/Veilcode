//! Vault plaintext model and its JSON form (SPEC §7, D5).

use super::project::ProjectKey;
use crate::error::{CoreError, Result};
use crate::hex;
use crate::scan::ScanOptions;
use crate::secret::SecretBytes;
use crate::token::{Token, TokenPrefix};
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

/// The longest session lifetime (D61): 365 days.
pub(crate) const MAX_TTL_SECS: u64 = 365 * 86_400;

/// One mask run (SPEC §6.4, §7). Holds no secret values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "SessionRecord")]
pub struct Session {
    pub id: SessionId,
    /// Unix seconds.
    pub created: u64,
    /// Unix seconds; the session is expired when `expires_at <= now` (D61).
    pub expires_at: u64,
    pub source_label: String,
    /// The walk options of the mask, reused by restore (D57r).
    pub scan_options: ScanOptions,
    pub tokens: Vec<Token>,
}

/// A session as read from JSON, before the D61 `expires_at` check.
#[derive(Deserialize)]
struct SessionRecord {
    id: SessionId,
    created: u64,
    expires_at: u64,
    source_label: String,
    scan_options: ScanOptions,
    tokens: Vec<Token>,
}

impl TryFrom<SessionRecord> for Session {
    type Error = &'static str;

    /// D61: `created < expires_at <= created + 365 days`.
    fn try_from(r: SessionRecord) -> std::result::Result<Self, Self::Error> {
        let max = r.created.saturating_add(MAX_TTL_SECS);
        if r.created >= r.expires_at || r.expires_at > max {
            return Err("invalid expires_at");
        }
        Ok(Session {
            id: r.id,
            created: r.created,
            expires_at: r.expires_at,
            source_label: r.source_label,
            scan_options: r.scan_options,
            tokens: r.tokens,
        })
    }
}

/// One vault entry: the secret value and where its token name came from.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub(crate) value: SecretBytes,
    pub(crate) name: String,
    pub(crate) rule_id: String,
    /// The prefix the token was made with (D138).
    pub(crate) prefix: TokenPrefix,
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("value", &self.value)
            .field("name", &self.name)
            .field("rule_id", &self.rule_id)
            .field("prefix", &self.prefix)
            .finish()
    }
}

/// Decrypted vault contents.
#[derive(Default, Clone)]
pub(crate) struct VaultData {
    pub(crate) sessions: Vec<Session>,
    pub(crate) entries: BTreeMap<Token, Entry>,
    /// The prefix remembered per project (D141); only custom prefixes.
    pub(crate) project_prefixes: BTreeMap<ProjectKey, TokenPrefix>,
}

#[derive(Serialize, Deserialize)]
struct Wire {
    version: u32,
    sessions: Vec<Session>,
    entries: BTreeMap<String, WireEntry>,
    /// D141: project key → custom prefix. Written only when not empty, so a
    /// vault without remembered prefixes keeps the pre-D141 JSON shape.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    project_prefixes: BTreeMap<String, String>,
}

/// JSON form of an entry; the hex value is wiped on drop.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct WireEntry {
    value_hex: String,
    name: String,
    rule_id: String,
    /// D138: written only when not `VEILCODE_`; absent reads as `VEILCODE_`,
    /// so a default-prefix vault keeps the pre-v1.4 JSON shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    prefix: Option<String>,
}

impl VaultData {
    /// Serialises to JSON in a buffer that is wiped on drop.
    pub(crate) fn to_json(&self) -> Result<Zeroizing<Vec<u8>>> {
        let entries = self
            .entries
            .iter()
            .map(|(t, e)| (t.as_str().to_string(), WireEntry::from(e)))
            .collect();
        let project_prefixes = self
            .project_prefixes
            .iter()
            .map(|(k, p)| (k.as_str().to_string(), p.as_str().to_string()))
            .collect();
        let wire = Wire {
            version: VERSION,
            sessions: self.sessions.clone(),
            entries,
            project_prefixes,
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
            let prefix = match &w.prefix {
                Some(p) => TokenPrefix::parse(p).map_err(|_| CoreError::VaultOpen)?,
                None => TokenPrefix::default(),
            };
            let token = Token::parse_with(t, &prefix).ok_or(CoreError::VaultOpen)?;
            let mut value = hex::decode(&w.value_hex).ok_or(CoreError::VaultOpen)?;
            let entry = Entry {
                // Moves the buffer out (no copy); the emptied wrapper drops.
                value: SecretBytes::new(std::mem::take(&mut *value)),
                name: w.name.clone(),
                rule_id: w.rule_id.clone(),
                prefix,
            };
            entries.insert(token, entry);
        }
        Ok(VaultData {
            sessions: wire.sessions.clone(),
            entries,
            project_prefixes: project_prefixes(&wire)?,
        })
    }
}

/// D141: every key is 64 lowercase hex characters and every prefix passes
/// the D138 rule, else the generic open error.
fn project_prefixes(wire: &Wire) -> Result<BTreeMap<ProjectKey, TokenPrefix>> {
    let mut out = BTreeMap::new();
    for (k, p) in &wire.project_prefixes {
        let key = ProjectKey::parse(k).ok_or(CoreError::VaultOpen)?;
        let prefix = TokenPrefix::parse(p).map_err(|_| CoreError::VaultOpen)?;
        out.insert(key, prefix);
    }
    Ok(out)
}

impl From<&Entry> for WireEntry {
    fn from(e: &Entry) -> Self {
        WireEntry {
            value_hex: hex::encode(e.value.expose()),
            name: e.name.clone(),
            rule_id: e.rule_id.clone(),
            prefix: (!e.prefix.is_default()).then(|| e.prefix.as_str().to_string()),
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
    let projects = wire.project_prefixes.len() * (64 + 16 + 8);
    entries + sessions + projects + 64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(token: &str, session_id: &str) -> Vec<u8> {
        format!(
            r#"{{"version":1,"sessions":[{{"id":"{session_id}","created":1,"expires_at":2,"source_label":"s","scan_options":{{"no_default_excludes":false}},"tokens":["{token}"]}}],"entries":{{}}}}"#
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

    /// A plaintext with one session and one entry `token` (with `prefix`
    /// as the raw JSON member text, or none).
    fn with_entry(token: &str, prefix: Option<&str>) -> Vec<u8> {
        let member = prefix.map_or_else(String::new, |p| format!(r#","prefix":{p}"#));
        format!(
            r#"{{"version":1,"sessions":[{{"id":"0123456789abcdef","created":1,"expires_at":2,"source_label":"s","scan_options":{{"no_default_excludes":false}},"tokens":["{token}"]}}],"entries":{{"{token}":{{"value_hex":"6869","name":"k","rule_id":"r"{member}}}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn t10_entry_without_prefix_reads_as_default_and_writes_without_it() {
        let data = VaultData::from_json(&with_entry("VEILCODE_K_ab000000", None)).expect("old");
        let (token, entry) = data.entries.iter().next().expect("entry");
        assert_eq!(token.as_str(), "VEILCODE_K_ab000000");
        assert_eq!(entry.prefix, TokenPrefix::default());
        assert_eq!(entry.value.expose(), b"hi");
        let json = String::from_utf8(data.to_json().expect("json").to_vec()).expect("utf8");
        assert!(!json.contains("prefix"), "default prefix written: {json}");
    }

    #[test]
    fn t10_custom_prefix_round_trips() {
        let raw = with_entry("Infra_Mask_K_ab000000", Some(r#""Infra_Mask_""#));
        let data = VaultData::from_json(&raw).expect("custom");
        let entry = data.entries.values().next().expect("entry");
        assert_eq!(entry.prefix.as_str(), "Infra_Mask_");
        let json = data.to_json().expect("json");
        assert!(String::from_utf8_lossy(&json).contains(r#""prefix":"Infra_Mask_""#));
        let again = VaultData::from_json(&json).expect("reopen");
        let keys: Vec<&str> = again.entries.keys().map(Token::as_str).collect();
        assert_eq!(keys, vec!["Infra_Mask_K_ab000000"]);
        assert_eq!(
            again.sessions[0].tokens[0].as_str(),
            "Infra_Mask_K_ab000000"
        );
    }

    #[test]
    fn t10_bad_prefix_or_mismatched_key_is_the_generic_error() {
        for (token, prefix) in [
            ("Infra_Mask_K_ab000000", None),
            ("Infra_Mask_K_ab000000", Some(r#""VEILCODE_""#)),
            ("VEILCODE_K_ab000000", Some(r#""Infra_Mask_""#)),
            ("Infra_Mask_K_ab000000", Some(r#""Infra_Mask""#)),
            ("Infra_Mask_K_ab000000", Some(r#""1nfra_Mask_""#)),
            ("Infra_Mask_K_ab000000", Some("7")),
        ] {
            let err = VaultData::from_json(&with_entry(token, prefix)).err();
            assert!(
                matches!(err, Some(CoreError::VaultOpen)),
                "{token} {prefix:?}"
            );
        }
    }
}
