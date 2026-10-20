use zeroize::Zeroizing;

/// Current wall-clock time as whole seconds since the Unix epoch.
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Fill a buffer with bytes produced by the operating system CSPRNG (`BCryptGenRandom`\r\n/// on Windows). Fails closed: if the OS source is unavailable the caller must\r\n/// abort rather than fall back to a predictable generator.\r\n/// Generate `len` cryptographically secure random bytes.
pub fn secure_random_bytes<const N: usize>() -> Result<[u8; N], getrandom::Error> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out)?;
    Ok(out)
}

/// Lowercase hex encoding for identifiers and salts that are stored verbatim.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// A 256-bit random identifier rendered as 64 hex characters.
pub fn random_id() -> Result<Zeroizing<String>, getrandom::Error> {
    let bytes = secure_random_bytes::<32>()?;
    Ok(Zeroizing::new(to_hex(&bytes)))
}

/// A 128-bit random Argon2id salt, rendered in PHC base64 (no padding).
/// The salt is not secret material: it is stored in the clear inside the PHC
/// hash string, so it is returned unwrapped.
pub fn random_salt() -> crate::error::AppResult<argon2::password_hash::SaltString> {
    use argon2::password_hash::SaltString;
    let bytes = secure_random_bytes::<16>()?;
    Ok(SaltString::encode_b64(&bytes)?)
}

/// Strip everything that is not an ASCII alphanumeric character and lowercase
/// the rest. Used for case-insensitive lookups of user supplied identifiers.
pub fn normalize_identifier(input: &str) -> String {
    input
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// True when the string contains ASCII control characters (including NUL),
/// which are never valid in the inputs accepted by this application.
pub fn contains_control_chars(input: &str) -> bool {
    input.chars().any(|c| c.is_control())
}