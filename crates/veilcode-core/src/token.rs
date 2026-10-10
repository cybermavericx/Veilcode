//! Placeholder tokens `VEILCODE_<NAME>_<HEX8>` (SPEC §4, D4).

use crate::error::Result;
use crate::hex;
use crate::rng::RandomSource;
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// The token regex from SPEC §4 v1.1 (no `\b`; the whole match is the key).
pub const TOKEN_PATTERN: &str = "VEILCODE_[A-Z0-9_]{1,24}_[0-9a-f]{8}";

/// The longest NAME (SPEC §4).
pub(crate) const NAME_MAX: usize = 24;

static TOKEN_RE: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new(TOKEN_PATTERN).ok());

/// The compiled token regex (`None` only if the pattern failed to compile).
pub(crate) fn token_regex() -> Option<&'static Regex> {
    TOKEN_RE.as_ref()
}

/// A placeholder token. Not secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Token(String);

impl TryFrom<String> for Token {
    type Error = &'static str;

    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        Token::parse(&s).ok_or("invalid token")
    }
}

impl Token {
    /// Accepts `s` only if the token regex matches its whole length.
    pub(crate) fn parse(s: &str) -> Option<Token> {
        let m = token_regex()?.find(s.as_bytes())?;
        (m.start() == 0 && m.end() == s.len()).then(|| Token(s.to_string()))
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// SPEC §4 NAME rule: uppercase, non-`[A-Z0-9]` to `_`, collapse, trim, 24 chars.
pub(crate) fn sanitize_name(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        let c = c.to_ascii_uppercase();
        let c = if c.is_ascii_uppercase() || c.is_ascii_digit() {
            c
        } else {
            '_'
        };
        if !(c == '_' && out.ends_with('_')) {
            out.push(c);
        }
    }
    let name: String = out.trim_matches('_').chars().take(NAME_MAX).collect();
    if name.is_empty() {
        "SECRET".to_string()
    } else {
        name
    }
}

/// Generates fresh tokens from an injected random source.
pub(crate) struct TokenGen<R: RandomSource> {
    rng: R,
}

impl<R: RandomSource> TokenGen<R> {
    pub(crate) fn new(rng: R) -> Self {
        TokenGen { rng }
    }

    /// A new token for `name`, regenerated while HEX8 has no `a`–`f`, the
    /// token `exists` in the vault, or it appears in any input haystack.
    pub(crate) fn generate(
        &mut self,
        name: &str,
        exists: impl Fn(&Token) -> bool,
        haystacks: &[&[u8]],
    ) -> Result<Token> {
        let name = sanitize_name(name);
        loop {
            let mut raw = [0u8; 4];
            self.rng.fill(&mut raw)?;
            let hex8 = hex::encode(&raw);
            if !hex8.bytes().any(|c| c.is_ascii_lowercase()) {
                continue;
            }
            let token = Token(format!("VEILCODE_{name}_{hex8}"));
            if !exists(&token) && !appears_in(token.as_str().as_bytes(), haystacks) {
                return Ok(token);
            }
        }
    }
}

fn appears_in(needle: &[u8], haystacks: &[&[u8]]) -> bool {
    haystacks
        .iter()
        .any(|h| h.windows(needle.len()).any(|w| w == needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::{OsRandom, SeqRandom};

    fn whole_match(s: &str) -> bool {
        let re = token_regex().expect("regex compiles");
        re.find(s.as_bytes())
            .is_some_and(|m| m.start() == 0 && m.end() == s.len())
    }

    #[test]
    fn t1_token_format_matches_whole_regex() {
        let mut tg = TokenGen::new(OsRandom);
        for i in 0..1000 {
            let name = format!("key.{i}");
            let t = tg.generate(&name, |_| false, &[]).expect("token");
            assert!(whole_match(t.as_str()), "{} does not match", t.as_str());
            assert!(t.as_str().starts_with(&format!("VEILCODE_KEY_{i}_")));
            assert_eq!(
                t.as_str().len(),
                "VEILCODE_KEY__".len() + i.to_string().len() + 8
            );
        }
    }

    #[test]
    fn t4_name_sanitisation_table() {
        assert_eq!(sanitize_name("db.password-1"), "DB_PASSWORD_1");
        assert_eq!(sanitize_name("__a__b__"), "A_B");
        assert_eq!(sanitize_name("$$$"), "SECRET");
        assert_eq!(sanitize_name(&"a".repeat(40)), "A".repeat(24));
    }

    #[test]
    fn t5_hex8_always_contains_a_letter() {
        let mut tg = TokenGen::new(SeqRandom::new(&[0, 0, 0, 0, 0x0a, 0, 0, 0]));
        let t = tg.generate("k", |_| false, &[]).expect("token");
        assert_eq!(t.as_str(), "VEILCODE_K_0a000000");
    }

    #[test]
    fn t6_tokens_adjacent_to_word_characters() {
        let t = TokenGen::new(OsRandom)
            .generate("db_pass", |_| false, &[])
            .expect("token");
        let t = t.as_str();
        let cases = [
            format!("x{t}yz"),
            format!("_{t}_"),
            format!("{t}9abcdef0"),
            format!("{t}_1a2b3c4d"),
        ];
        let re = token_regex().expect("regex compiles");
        for case in &cases {
            let found: Vec<&[u8]> = re
                .find_iter(case.as_bytes())
                .map(|m| m.as_bytes())
                .collect();
            assert_eq!(found, vec![t.as_bytes()], "case {case}");
        }
    }

    #[test]
    fn t7_token_collision_with_the_input() {
        let rng = SeqRandom::new(&[0xab, 0xcd, 0xef, 0x01, 0x12, 0x34, 0x56, 0xab]);
        let input = b"let a = \"VEILCODE_API_KEY_abcdef01\";".to_vec();
        let other = b"unrelated".to_vec();
        let t = TokenGen::new(rng)
            .generate("api key", |_| false, &[&other, &input])
            .expect("token");
        assert_eq!(t.as_str(), "VEILCODE_API_KEY_123456ab");
    }

    #[test]
    fn token_exists_in_vault_is_regenerated() {
        let rng = SeqRandom::new(&[0xab, 0, 0, 0, 0xcd, 0, 0, 0]);
        let first = Token("VEILCODE_K_ab000000".into());
        let t = TokenGen::new(rng)
            .generate("k", |t| *t == first, &[])
            .expect("token");
        assert_eq!(t.as_str(), "VEILCODE_K_cd000000");
    }

    #[test]
    fn token_parse_requires_whole_match() {
        assert!(Token::parse("VEILCODE_K_ab000000").is_some());
        assert!(Token::parse("xVEILCODE_K_ab000000").is_none());
        assert!(Token::parse("VEILCODE_K_ab0000001").is_none());
        assert!(Token::parse("VEILCODE_k_ab000000").is_none());
    }
}
