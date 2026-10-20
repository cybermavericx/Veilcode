//! Placeholder tokens `<PREFIX><NAME>_<HEX8>` (SPEC §4, D4, D138).

use crate::error::{CoreError, Result};
use crate::hex;
use crate::rng::RandomSource;
use serde::{Deserialize, Serialize};

/// The token regex for the default prefix, SPEC §4 (no `\b`; the whole
/// match is the key). Other prefixes are matched by `KnownPrefixes`.
pub const TOKEN_PATTERN: &str = "VEILCODE_[A-Z0-9_]{1,24}_[0-9a-f]{8}";

/// The default prefix (SPEC §4).
pub const DEFAULT_PREFIX: &str = "VEILCODE_";

/// The longest NAME (SPEC §4).
pub(crate) const NAME_MAX: usize = 24;
/// The longest prefix (D138).
const PREFIX_MAX: usize = 16;
const HEX_LEN: usize = 8;
/// The longest token: 16-char prefix + 24 NAME chars + `_` + 8 hex.
pub(crate) const MAX_TOKEN_LEN: usize = PREFIX_MAX + NAME_MAX + 1 + HEX_LEN;

/// The compiled default-prefix token regex (tests compare against it).
#[cfg(test)]
pub(crate) fn token_regex() -> Option<&'static regex::bytes::Regex> {
    static RE: std::sync::LazyLock<Option<regex::bytes::Regex>> =
        std::sync::LazyLock::new(|| regex::bytes::Regex::new(TOKEN_PATTERN).ok());
    RE.as_ref()
}

/// A placeholder prefix that passed the D138 rule. Not secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenPrefix(String);

impl TokenPrefix {
    /// D138: 2–16 ASCII characters, a letter first, then letters, digits
    /// or `_`, ending with `_`. A prefix other than `VEILCODE_` itself must
    /// not start with `VEILCODE_` (L4: its tokens would also look like
    /// default-prefix tokens).
    pub fn parse(s: &str) -> Result<TokenPrefix> {
        if s != DEFAULT_PREFIX && s.starts_with(DEFAULT_PREFIX) {
            return Err(CoreError::ReservedTokenPrefix);
        }
        let b = s.as_bytes();
        let ok = (2..=PREFIX_MAX).contains(&b.len())
            && b[0].is_ascii_alphabetic()
            && b.ends_with(b"_")
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_');
        if ok {
            Ok(TokenPrefix(s.to_string()))
        } else {
            Err(CoreError::BadTokenPrefix)
        }
    }

    /// The prefix text.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// True for `VEILCODE_`.
    pub(crate) fn is_default(&self) -> bool {
        self.0 == DEFAULT_PREFIX
    }
}

impl Default for TokenPrefix {
    fn default() -> Self {
        TokenPrefix(DEFAULT_PREFIX.to_string())
    }
}

/// A placeholder token. Not secret.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Token(String);

impl TryFrom<String> for Token {
    type Error = &'static str;

    /// Accepts a token of any prefix that passes the D138 rule (a session
    /// lists tokens of every prefix it used).
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        let fits = |n: usize| {
            let p = s.get(..n).and_then(|p| TokenPrefix::parse(p).ok());
            p.is_some_and(|p| Token::parse_with(&s, &p).is_some())
        };
        if (2..=PREFIX_MAX).any(fits) {
            Ok(Token(s))
        } else {
            Err("invalid token")
        }
    }
}

impl Token {
    /// A whole default-prefix token, or `None` (tests).
    #[cfg(test)]
    pub(crate) fn parse(s: &str) -> Option<Token> {
        Token::parse_with(s, &TokenPrefix::default())
    }

    /// A whole token of `prefix`: the prefix, then `[A-Z0-9_]{1,24}_[0-9a-f]{8}`
    /// (with an `a`–`f` in HEX8 for a custom prefix, see `shape_ends`).
    pub(crate) fn parse_with(s: &str, prefix: &TokenPrefix) -> Option<Token> {
        let rest = s.as_bytes().strip_prefix(prefix.as_str().as_bytes())?;
        shape_ends(rest, 0, prefix)
            .contains(&rest.len())
            .then(|| Token(s.to_string()))
    }

    /// The token text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The ends of `[A-Z0-9_]{1,24}_[0-9a-f]{8}` matches that start at
/// `name_at`, longest NAME first (the order of the greedy regex). For a
/// custom `prefix`, HEX8 must also hold an `a`–`f`, as every generated
/// HEX8 does (D4, L3); the default prefix keeps the SPEC §4 regex.
pub(crate) fn shape_ends(hay: &[u8], name_at: usize, prefix: &TokenPrefix) -> Vec<usize> {
    let need_letter = !prefix.is_default();
    let is_name = |b: &&u8| b.is_ascii_uppercase() || b.is_ascii_digit() || **b == b'_';
    let is_hex = |b: &u8| matches!(b, b'0'..=b'9' | b'a'..=b'f');
    let tail = hay.get(name_at..).unwrap_or_default();
    let run = tail.iter().take(NAME_MAX).take_while(is_name).count();
    let hex_after = |n: usize| {
        let hex = tail.get(n + 1..n + 1 + HEX_LEN);
        let letter = |h: &[u8]| !need_letter || h.iter().any(|b| matches!(b, b'a'..=b'f'));
        tail.get(n) == Some(&b'_') && hex.is_some_and(|h| h.iter().all(is_hex) && letter(h))
    };
    let names = (1..=run).rev().filter(|&n| hex_after(n));
    names.map(|n| name_at + n + 1 + HEX_LEN).collect()
}

/// The prefixes restore looks for: those in the vault plus the default,
/// sorted and without duplicates (D138).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnownPrefixes(Vec<TokenPrefix>);

impl Default for KnownPrefixes {
    fn default() -> Self {
        KnownPrefixes(vec![TokenPrefix::default()])
    }
}

impl KnownPrefixes {
    pub(crate) fn new<'a>(prefixes: impl IntoIterator<Item = &'a TokenPrefix>) -> Self {
        let mut list: Vec<TokenPrefix> = prefixes.into_iter().cloned().collect();
        list.push(TokenPrefix::default());
        list.sort();
        list.dedup();
        KnownPrefixes(list)
    }

    /// These prefixes plus `extra`.
    pub(crate) fn with(&self, extra: &TokenPrefix) -> Self {
        KnownPrefixes::new(self.0.iter().chain(std::iter::once(extra)))
    }

    #[cfg(test)]
    pub(crate) fn list(&self) -> &[TokenPrefix] {
        &self.0
    }

    /// The known prefixes that start at offset `at` of `hay`.
    pub(crate) fn at<'a>(
        &'a self,
        hay: &'a [u8],
        at: usize,
    ) -> impl Iterator<Item = &'a TokenPrefix> + 'a {
        let rest = hay.get(at..).unwrap_or_default();
        let starts = move |p: &&TokenPrefix| rest.starts_with(p.as_str().as_bytes());
        self.0.iter().filter(starts)
    }

    /// The first offset `>= from` where a known prefix starts.
    pub(crate) fn next_start(&self, hay: &[u8], from: usize) -> Option<usize> {
        let firsts: Vec<u8> = self.0.iter().filter_map(|p| p.0.bytes().next()).collect();
        let from = from.min(hay.len());
        let candidates = hay[from..].iter().enumerate();
        let mut hits = candidates.filter(|(_, b)| firsts.contains(b));
        hits.find(|&(i, _)| self.at(hay, from + i).next().is_some())
            .map(|(i, _)| from + i)
    }

    /// True if `span` is exactly a token of a known prefix (D48a, D138).
    pub(crate) fn is_exact(&self, span: &[u8]) -> bool {
        let Ok(s) = std::str::from_utf8(span) else {
            return false;
        };
        self.at(span, 0).any(|p| Token::parse_with(s, p).is_some())
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

    /// A new `prefix` token for `name`, regenerated while HEX8 has no
    /// `a`–`f`, the token `exists` in the vault, or it appears in any
    /// input haystack.
    pub(crate) fn generate(
        &mut self,
        name: &str,
        prefix: &TokenPrefix,
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
            let token = Token(format!("{}{name}_{hex8}", prefix.as_str()));
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

    fn dflt() -> TokenPrefix {
        TokenPrefix::default()
    }

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
            let t = tg.generate(&name, &dflt(), |_| false, &[]).expect("token");
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
        let t = tg.generate("k", &dflt(), |_| false, &[]).expect("token");
        assert_eq!(t.as_str(), "VEILCODE_K_0a000000");
    }

    #[test]
    fn t6_tokens_adjacent_to_word_characters() {
        let t = TokenGen::new(OsRandom)
            .generate("db_pass", &dflt(), |_| false, &[])
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
            .generate("api key", &dflt(), |_| false, &[&other, &input])
            .expect("token");
        assert_eq!(t.as_str(), "VEILCODE_API_KEY_123456ab");
    }

    #[test]
    fn token_exists_in_vault_is_regenerated() {
        let rng = SeqRandom::new(&[0xab, 0, 0, 0, 0xcd, 0, 0, 0]);
        let first = Token("VEILCODE_K_ab000000".into());
        let t = TokenGen::new(rng)
            .generate("k", &dflt(), |t| *t == first, &[])
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

    fn prefix(s: &str) -> TokenPrefix {
        TokenPrefix::parse(s).expect("valid prefix")
    }

    #[test]
    fn t9_prefix_rule_table() {
        let sixteen = format!("A{}_", "b".repeat(14));
        assert_eq!(sixteen.len(), 16);
        for ok in ["VEILCODE_", "Infra_Mask_", "ab_", "Z9_", "a__", &sixteen] {
            assert_eq!(prefix(ok).as_str(), ok, "{ok}");
        }
        let seventeen = format!("A{}_", "b".repeat(15));
        let bad = [
            "", "A", "_", "_A_", "1A_", "AB", "A-B_", "\u{c4}_", "A B_", "A_b", &seventeen,
        ];
        for b in bad {
            let err = TokenPrefix::parse(b).expect_err(b);
            assert!(matches!(err, CoreError::BadTokenPrefix), "{b}");
            let msg = err.to_string();
            assert!(
                msg.contains("2\u{2013}16") && msg.ends_with("ending with _"),
                "{msg}"
            );
            if b.len() > 1 {
                assert!(!msg.contains(b), "message quotes the input {b}");
            }
        }
        assert_eq!(TokenPrefix::default().as_str(), "VEILCODE_");
    }

    #[test]
    fn t9_custom_prefix_token_format() {
        let p = prefix("Infra_Mask_");
        let mut tg = TokenGen::new(OsRandom);
        for i in 0..200 {
            let name = format!("db.pass{i}");
            let t = tg.generate(&name, &p, |_| false, &[]).expect("token");
            let s = t.as_str();
            assert!(s.starts_with(&format!("Infra_Mask_DB_PASS{i}_")), "{s}");
            assert_eq!(Token::parse_with(s, &p), Some(t.clone()));
            assert_eq!(Token::parse(s), None, "not a default-prefix token");
            let hex8 = &s[s.len() - 8..];
            assert!(hex8.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')));
        }
    }

    #[test]
    fn t9_custom_prefix_hex_letter_and_collision() {
        let p = prefix("Infra_Mask_");
        let mut tg = TokenGen::new(SeqRandom::new(&[0, 0, 0, 0, 0x0a, 0, 0, 0]));
        let t = tg.generate("k", &p, |_| false, &[]).expect("token");
        assert_eq!(t.as_str(), "Infra_Mask_K_0a000000");
        let rng = SeqRandom::new(&[0xab, 0xcd, 0xef, 0x01, 0x12, 0x34, 0x56, 0xab]);
        let input = b"x = Infra_Mask_API_KEY_abcdef01;".to_vec();
        let t = TokenGen::new(rng)
            .generate("api key", &p, |_| false, &[&input])
            .expect("token");
        assert_eq!(t.as_str(), "Infra_Mask_API_KEY_123456ab");
    }

    #[test]
    fn t9_parse_with_and_any_prefix_shape() {
        let p = prefix("Infra_Mask_");
        assert!(Token::parse_with("Infra_Mask_K_ab000000", &p).is_some());
        assert!(Token::parse_with("Infra_Mask_k_ab000000", &p).is_none());
        assert!(Token::parse_with("Infra_Mask__ab000000", &p).is_none());
        assert!(Token::parse_with("Infra_Mask_K_ab00000", &p).is_none());
        assert!(Token::parse_with("Infra_Mask_K_AB000000", &p).is_none());
        assert!(Token::parse_with("VEILCODE_K_ab000000", &p).is_none());
        let long = format!("Infra_Mask_{}_ab000000", "N".repeat(25));
        assert!(Token::parse_with(&long, &p).is_none());
        for ok in [
            "Infra_Mask_K_ab000000",
            "VEILCODE_K_ab000000",
            "ab_K_ab000000",
        ] {
            assert!(Token::try_from(ok.to_string()).is_ok(), "{ok}");
        }
        for bad in [
            "1x_K_ab000000",
            "-x_K_ab000000",
            "K_ab000000",
            "Infra_Mask_K_ab0000001",
        ] {
            assert!(Token::try_from(bad.to_string()).is_err(), "{bad}");
        }
    }

    #[test]
    fn t9_known_prefixes_find_starts_and_exact_tokens() {
        let known = KnownPrefixes::new([&prefix("Infra_Mask_"), &prefix("ab_")]);
        let names: Vec<&str> = known.list().iter().map(TokenPrefix::as_str).collect();
        assert_eq!(names, vec!["Infra_Mask_", "VEILCODE_", "ab_"]);
        let hay = b"xx VEILCODE_ yy Infra_Mask_ zz ab_";
        assert_eq!(known.next_start(hay, 0), Some(3));
        assert_eq!(known.next_start(hay, 4), Some(16));
        assert_eq!(known.next_start(hay, 17), Some(31));
        assert_eq!(known.next_start(hay, 32), None);
        assert!(known.is_exact(b"Infra_Mask_K_ab000000"));
        assert!(known.is_exact(b"VEILCODE_K_ab000000"));
        assert!(!known.is_exact(b"Other_K_ab000000"));
        assert!(!KnownPrefixes::default().is_exact(b"Infra_Mask_K_ab000000"));
        let hay = b"Infra_Mask_A_B_ab000000_cd000000";
        let custom = prefix("Infra_Mask_");
        assert_eq!(shape_ends(hay, 11, &custom), vec![23]);
        let hay = b"Infra_Mask_A_B_CD_ab000000";
        assert_eq!(shape_ends(hay, 11, &custom), vec![26]);
    }

    #[test]
    fn t9_prefixes_starting_with_veilcode_are_reserved() {
        assert!(TokenPrefix::parse("VEILCODE_").is_ok());
        assert!(TokenPrefix::parse("VEILCODEX_").is_ok());
        for bad in ["VEILCODE_X_", "VEILCODE__", "VEILCODE_A1_"] {
            let err = TokenPrefix::parse(bad).expect_err(bad);
            assert!(matches!(err, CoreError::ReservedTokenPrefix), "{bad}");
            assert_eq!(
                err.to_string(),
                "a placeholder prefix other than VEILCODE_ must not start with VEILCODE_"
            );
        }
    }

    #[test]
    fn t9_custom_prefix_hex8_needs_a_letter_default_unchanged() {
        let known = KnownPrefixes::new([&prefix("Infra_Mask_")]);
        assert!(!known.is_exact(b"Infra_Mask_K_12345678"));
        assert!(known.is_exact(b"Infra_Mask_K_1234567a"));
        assert!(
            known.is_exact(b"VEILCODE_K_12345678"),
            "default prefix changed"
        );
        assert!(Token::parse_with("Infra_Mask_K_12345678", &prefix("Infra_Mask_")).is_none());
        assert!(Token::try_from("Infra_Mask_K_12345678".to_string()).is_err());
        assert!(Token::try_from("VEILCODE_K_12345678".to_string()).is_ok());
    }
}
