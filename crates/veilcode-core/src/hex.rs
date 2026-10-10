//! Lowercase hex encode/decode (no dependency).

use zeroize::Zeroizing;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 0x0f)]));
    }
    out
}

/// Decodes lowercase hex; `None` on odd length or any other character.
/// The buffer is pre-sized (no realloc copies) and wiped if decoding fails.
pub(crate) fn decode(s: &str) -> Option<Zeroizing<Vec<u8>>> {
    let raw = s.as_bytes();
    let (pairs, rest) = raw.as_chunks::<2>();
    if !rest.is_empty() {
        return None;
    }
    let mut out = Zeroizing::new(Vec::with_capacity(raw.len() / 2));
    for [hi, lo] in pairs {
        out.push(nibble(*hi)? << 4 | nibble(*lo)?);
    }
    Some(out)
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip_and_rejects() {
        assert_eq!(encode(&[0x00, 0xff, 0x0a, 0xb1]), "00ff0ab1");
        assert_eq!(
            decode("00ff0ab1").as_deref().map(Vec::as_slice),
            Some([0x00, 0xff, 0x0a, 0xb1].as_slice())
        );
        assert!(decode("abc").is_none());
        assert!(decode("AB").is_none());
        assert!(decode("zz").is_none());
        assert_eq!(decode("").map(|v| v.len()), Some(0));
    }
}
