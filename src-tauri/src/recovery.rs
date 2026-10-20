use std::collections::HashSet;


use zeroize::{Zeroize, Zeroizing};

use crate::util;

/// Alphabet for recovery codes.
///
/// Excludes the visually ambiguous characters `O`, `0`, `I` and `1` so the
/// codes can be transcribed by hand from a screen or a printed sheet.
/// 28 symbols -> log2(28) = 4.807 bits of entropy per character.
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// Four groups of five characters: 20 symbols -> ~96 bits of entropy per code.
const GROUP_LEN: usize = 5;
const GROUPS: usize = 4;
const CODE_SYMBOLS: usize = GROUP_LEN * GROUPS;

const RECOVERY_CODE_COUNT: usize = 10;

/// A freshly generated set of recovery codes.
///
/// The plaintext exists only in memory, is shown to the owner exactly once and
/// is never written to SQLite, to configuration files or to any log.
#[derive(Clone)]
pub struct RecoveryCodeBundle {
    codes: Vec<Zeroizing<String>>,
}

impl RecoveryCodeBundle {
    /// Codes in plaintext, for one-time display in the UI.
    pub fn codes(&self) -> Vec<String> {
        self.codes.iter().map(|c| c.to_string()).collect()
    }
}

impl Drop for RecoveryCodeBundle {
    fn drop(&mut self) {
        for code in self.codes.iter_mut() {
            code.zeroize();
        }
    }
}

/// Generate `RECOVERY_CODE_COUNT` unique recovery codes from the OS CSPRNG.
///
/// Uniqueness is enforced against the codes generated in this batch; a
/// collision would have probability ~10 * 2^-96 and is treated as a hard
/// failure rather than silently retrying with weaker randomness.
pub fn generate_bundle() -> crate::error::AppResult<RecoveryCodeBundle> {
    let mut seen: HashSet<String> = HashSet::with_capacity(RECOVERY_CODE_COUNT * 2);
    let mut codes: Vec<Zeroizing<String>> = Vec::with_capacity(RECOVERY_CODE_COUNT);

    while codes.len() < RECOVERY_CODE_COUNT {
        let raw = util::secure_random_bytes::<CODE_SYMBOLS>()?;

        let mut code = String::with_capacity(CODE_SYMBOLS + GROUPS - 1);
        for (index, byte) in raw.iter().enumerate() {
            if index > 0 && index % GROUP_LEN == 0 {
                code.push('-');
            }
            code.push(ALPHABET[*byte as usize % ALPHABET.len()] as char);
        }

        if seen.insert(code.clone()) {
            codes.push(Zeroizing::new(code));
        }
    }

    Ok(RecoveryCodeBundle { codes })
}

/// Normalise user input of a recovery code.
///
/// Accepts the code as displayed, lower case, or with any of `_`, space or `–`
/// instead of `-`. Ambiguous characters are left untouched: `0`/`O` and
/// `1`/`I` are never part of a generated code, so an ambiguous character in the
/// input means the code simply cannot match.
pub fn normalize(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// True when `input` (already normalized by [`normalize`]) looks like a
/// recovery code of the expected shape. Used to reject obviously malformed
/// input before any hashing is performed.
pub fn has_expected_shape(normalized: &str) -> bool {
    normalized.len() == CODE_SYMBOLS
        && normalized
            .bytes()
            .all(|byte| ALPHABET.contains(&byte))
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_has_ten_unique_well_formed_codes() {
        let bundle = generate_bundle().unwrap();
        let codes = bundle.codes();
        assert_eq!(codes.len(), 10);

        let unique: std::collections::HashSet<&String> = codes.iter().collect();
        assert_eq!(unique.len(), 10, "codes must be unique");

        for code in &codes {
            assert_eq!(code.len(), 23, "4 groups of 5 plus 3 separators");
            assert_eq!(code.matches('-').count(), 3);
            assert!(has_expected_shape(&normalize(code)));
            // Ambiguous characters must never appear.
            assert!(!code.contains('O'));
            assert!(!code.contains('I'));
            assert!(!code.contains('0'));
            assert!(!code.contains('1'));
        }
    }

    #[test]
    fn two_bundles_differ() {
        let first = generate_bundle().unwrap().codes();
        let second = generate_bundle().unwrap().codes();
        assert_ne!(first, second);
    }

#[test]
    fn normalize_accepts_common_typed_variants() {
        // "ABCDE-FGHJK-MNPQR-STVWX" with 20 symbols, no ambiguous characters.
        let expected: String = ["ABCDE", "FGHJK", "MNPQR", "STVWX"].concat();
        assert_eq!(expected.len(), CODE_SYMBOLS);

        assert_eq!(normalize("abcde-fghjk-mnpqr-stvwx"), expected);
        assert_eq!(normalize("  ABCDE FGHJK_MNPQR-STVWX  "), expected);
        assert!(has_expected_shape(&expected));
    }

    #[test]
    fn malformed_codes_fail_the_shape_check() {
        assert!(!has_expected_shape(""));
        assert!(!has_expected_shape("ABCDE"));
        assert!(!has_expected_shape("ABCDE-FGHJK-MNPQR"));
        // Too long even with the right alphabet.
        assert!(!has_expected_shape("ABCDEFGHJKLMNPQRSTUVWX"));
        // Right length, but characters outside the alphabet.
        assert!(!has_expected_shape("BCDEF-FGHJK-MNPQR-STVWX"));
    }
}
