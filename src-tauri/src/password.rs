use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier},
    Algorithm, Argon2, Params, Version,
};
use zeroize::Zeroizing;

use crate::error::AppResult;
use crate::util;

/// Argon2id parameters for the account password.
///
/// 46 MiB / 1 pass / 1 lane follows the OWASP Password Storage Cheat Sheet
/// recommendation for Argon2id. The parameters are pinned in code and encoded
/// into the PHC string, so an upgrade never invalidates existing hashes.
const PASSWORD_M_COST_KIB: u32 = 47_152; // 46 MiB
const PASSWORD_T_COST: u32 = 1;
const PASSWORD_P_COST: u32 = 1;

/// Argon2id parameters for recovery codes.
///
/// Slightly cheaper than the password parameters because a single verification
/// may have to check several codes, while still being memory hard.
const RECOVERY_M_COST_KIB: u32 = 19_456; // 19 MiB
const RECOVERY_T_COST: u32 = 2;
const RECOVERY_P_COST: u32 = 1;

fn password_hasher() -> AppResult<Argon2<'static>> {
    let params = Params::new(
        PASSWORD_M_COST_KIB,
        PASSWORD_T_COST,
        PASSWORD_P_COST,
        None,
    )?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn recovery_hasher() -> AppResult<Argon2<'static>> {
    let params = Params::new(RECOVERY_M_COST_KIB, RECOVERY_T_COST, RECOVERY_P_COST, None)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hash an account password with Argon2id and a freshly generated 128-bit salt.
///
/// Returns a PHC formatted string (`$argon2id$v=19$m=...,t=...,p=...$salt$hash`)
/// that is safe to persist. The plaintext is zeroized by the caller.
pub fn hash_password(password: &str) -> AppResult<Zeroizing<String>> {
    let salt = util::random_salt()?;
    let hasher = password_hasher()?;
    let hash = hasher.hash_password(password.as_bytes(), &salt)?;
    Ok(Zeroizing::new(hash.to_string()))
}

/// Constant-time verification of a password against its stored PHC string.
///
/// Returns `false` for any malformed stored value instead of an error, so a
/// corrupted record cannot be distinguished from a wrong password by an
/// attacker probing the command surface.
pub fn verify_password(password: &str, stored_phc: &str) -> bool {
    let parsed = match PasswordHash::new(stored_phc) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    match password_hasher() {
        Ok(hasher) => hasher.verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Hash a single recovery code with Argon2id and a unique salt.
pub fn hash_recovery_code(code: &str) -> AppResult<Zeroizing<String>> {
    let salt = util::random_salt()?;
    let hasher = recovery_hasher()?;
    let hash = hasher.hash_password(code.as_bytes(), &salt)?;
    Ok(Zeroizing::new(hash.to_string()))
}

/// Verify a recovery code against a stored PHC string.
pub fn verify_recovery_code(code: &str, stored_phc: &str) -> bool {
    let parsed = match PasswordHash::new(stored_phc) {
        Ok(parsed) => parsed,
        Err(_) => return false,
    };
    match recovery_hasher() {
        Ok(hasher) => hasher.verify_password(code.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_round_trip() {
        let hash = hash_password("Correct-Horse-9!").unwrap();
        assert!(verify_password("Correct-Horse-9!", hash.as_str()));
        assert!(!verify_password("correct-horse-9!", hash.as_str()));
        assert!(!verify_password("", hash.as_str()));
    }

    #[test]
    fn hashing_is_salted_per_call() {
        let a = hash_password("Correct-Horse-9!").unwrap();
        let b = hash_password("Correct-Horse-9!").unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[test]
    fn malformed_stored_hash_is_rejected_without_error() {
        assert!(!verify_password("anything", "not-a-phc-string"));
        assert!(!verify_recovery_code("ANYTHING", ""));
    }

    #[test]
    fn recovery_code_round_trip() {
        let hash = hash_recovery_code("ABCDE-FGHJK-MNPQR-STVWX").unwrap();
        assert!(verify_recovery_code(
            "ABCDE-FGHJK-MNPQR-STVWX",
            hash.as_str()
        ));
        assert!(!verify_recovery_code(
            "ABCDE-FGHJK-MNPQR-STVWY",
            hash.as_str()
        ));
    }
}
