use crate::error::{AppError, AppResult};

/// Maximum accepted lengths keep every input well inside the 1 MB Tauri IPC
/// payload budget and prevent abuse of the hashing routine.
const MAX_NAME_LEN: usize = 100;
const MAX_EMAIL_LEN: usize = 254;
const MAX_PASSWORD_LEN: usize = 256;
const MIN_PASSWORD_LEN: usize = 12;

/// Small deny-list of passwords that trivially satisfy the character rules.
const COMMON_PASSWORDS: &[&str] = &[
    "password1234",
    "password12345",
    "qwertyuiop12",
    "123456789012",
    "administrator",
    "letmein12345",
    "iloveyou1234",
    "welcome12345",
    "backmeup12345",
    "database12345",
];

/// Validate and normalise the display name.
pub fn validate_full_name(raw: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(
            "Full name contains characters that are not allowed.",
        ));
    }

    let name = raw.trim();

    if name.is_empty() {
        return Err(AppError::invalid_input("Full name is required."));
    }
    if name.chars().count() < 2 {
        return Err(AppError::invalid_input(
            "Full name must be at least 2 characters.",
        ));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(AppError::invalid_input(format!(
            "Full name must be {MAX_NAME_LEN} characters or fewer."
        )));
    }

    Ok(name.to_string())
}

/// Validate and normalise an email address.
///
/// Deliberately conservative: ASCII only, one `@`, a dotted domain with an
/// alphabetic TLD. This is an identifier we only ever compare locally, so
/// there is no need to accept exotic (RFC 5322) forms.
pub fn validate_email(raw: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input("Email address is not valid."));
    }

    let email = raw.trim();

    if email.is_empty() {
        return Err(AppError::invalid_input("Email address is required."));
    }
    if email.len() > MAX_EMAIL_LEN {
        return Err(AppError::invalid_input("Email address is too long."));
    }
    if email.chars().any(|c| c.is_whitespace()) {
        return Err(AppError::invalid_input("Email address is not valid."));
    }
    if !email.is_ascii() {
        return Err(AppError::invalid_input(
            "Email address may only contain standard ASCII characters.",
        ));
    }

    let mut parts = email.split('@');
    let (local, domain) = match (parts.next(), parts.next(), parts.next()) {
        (Some(local), Some(domain), None) => (local, domain),
        _ => {
            return Err(AppError::invalid_input(
                "Enter a valid email address, for example name@example.com.",
            ))
        }
    };

    if local.is_empty() || local.len() > 64 {
        return Err(AppError::invalid_input(
            "Enter a valid email address, for example name@example.com.",
        ));
    }

    let valid_local = local
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    if !valid_local || local.starts_with('.') || local.ends_with('.') || local.contains("..") {
        return Err(AppError::invalid_input(
            "Enter a valid email address, for example name@example.com.",
        ));
    }

    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 {
        return Err(AppError::invalid_input(
            "Enter a valid email address, for example name@example.com.",
        ));
    }

    for label in &labels {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(AppError::invalid_input(
                "Enter a valid email address, for example name@example.com.",
            ));
        }
    }

    let tld = labels[labels.len() - 1];
    if tld.len() < 2 || !tld.chars().all(|c| c.is_ascii_alphabetic()) {
        return Err(AppError::invalid_input(
            "Enter a valid email address, for example name@example.com.",
        ));
    }

    Ok(email.to_ascii_lowercase())
}

/// Enforce the password policy. Returns the trimmed-length-independent
/// password unchanged; callers must clear it after use.
pub fn validate_password(password: &str) -> AppResult<()> {
    if crate::util::contains_control_chars(password) {
        return Err(AppError::invalid_input(
            "Password contains characters that are not allowed.",
        ));
    }

    let length = password.chars().count();

    if length < MIN_PASSWORD_LEN {
        return Err(AppError::invalid_input(format!(
            "Password must be at least {MIN_PASSWORD_LEN} characters."
        )));
    }
    if length > MAX_PASSWORD_LEN {
        return Err(AppError::invalid_input(format!(
            "Password must be {MAX_PASSWORD_LEN} characters or fewer."
        )));
    }

    let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
    let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
    let has_digit = password.chars().any(|c| c.is_ascii_digit());
    let has_symbol = password
        .chars()
        .any(|c| !c.is_ascii_alphanumeric() && !c.is_whitespace());

    if !(has_lower && has_upper && has_digit && has_symbol) {
        return Err(AppError::invalid_input(
            "Password must include a lowercase letter, an uppercase letter, a number and a symbol.",
        ));
    }

    let lowered: String = password
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    if COMMON_PASSWORDS.contains(&lowered.as_str()) {
        return Err(AppError::invalid_input(
            "That password is too common. Choose something less predictable.",
        ));
    }

    Ok(())
}

/// Validate a password plus its confirmation.
pub fn validate_password_pair(password: &str, confirmation: &str) -> AppResult<()> {
    if password != confirmation {
        return Err(AppError::invalid_input("Passwords do not match."));
    }
    validate_password(password)
}

// ---------------------------------------------------------------------------
// Database connection records
//
// These constrain everything that crosses the IPC boundary before it can reach
// SQLite. Every bound is an explicit allowlist rather than a deny-list of
// "bad" characters, and nothing here is interpreted as a path, a command or
// SQL: the values are only ever bound as parameters.
// ---------------------------------------------------------------------------

const MAX_LABEL_LEN: usize = 100;
const MAX_HOST_LEN: usize = 253;
const MAX_DB_NAME_LEN: usize = 128;
const MAX_USERNAME_LEN: usize = 128;
const MAX_PORT: i64 = 65_535;

/// A short human-facing name for a database connection or a destination.
pub fn validate_label(raw: &str, field: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(format!(
            "{field} contains characters that are not allowed."
        )));
    }

    let value = raw.trim();

    if value.is_empty() {
        return Err(AppError::invalid_input(format!("{field} is required.")));
    }
    if value.chars().count() > MAX_LABEL_LEN {
        return Err(AppError::invalid_input(format!(
            "{field} must be {MAX_LABEL_LEN} characters or fewer."
        )));
    }

    Ok(value.to_string())
}

/// Host name or IP literal.
///
/// BackMeUp does not dial this in the current phase; it is validated anyway so
/// the stored record is well formed from the moment it is created. The
/// character set covers DNS names and IPv6 literals, and nothing else, which
/// rules out `..` traversal shapes, NUL bytes and shell metacharacters.
pub fn validate_host(raw: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(
            "Host contains characters that are not allowed.",
        ));
    }

    let host = raw.trim();

    if host.is_empty() {
        return Err(AppError::invalid_input("Host is required."));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(AppError::invalid_input("Host is too long."));
    }
    if !host.is_ascii() {
        return Err(AppError::invalid_input(
            "Host may only contain standard ASCII characters.",
        ));
    }

    // A host containing a colon is an IP literal and must use the bracketed
    // form (`[::1]`). Accepting a bare, colon-bearing host would let
    // `..`/separator shapes through the label checks below, so the two forms
    // are validated separately.
    if host.contains(':') {
        let Some(inner) = host.strip_prefix('[').and_then(|rest| rest.strip_suffix(']')) else {
            return Err(AppError::invalid_input(
                "Enter an IPv6 address in brackets, for example [::1].",
            ));
        };

        if !is_valid_ipv6(inner) {
            return Err(AppError::invalid_input("Enter a valid IPv6 address."));
        }

        return Ok(host.to_ascii_lowercase());
    }

    let allowed = host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));

    if !allowed
        || host.starts_with('.')
        || host.starts_with('-')
        || host.ends_with('.')
        || host.ends_with('-')
        || host.contains("..")
    {
        return Err(AppError::invalid_input("Enter a valid host name or IP address."));
    }

    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(AppError::invalid_input("Enter a valid host name or IP address."));
        }
    }

    Ok(host.to_ascii_lowercase())
}

/// TCP port. `None` is legitimate: engines reached over a local socket have no
/// port, and an omitted port simply means "not recorded yet".
pub fn validate_port(raw: Option<i64>) -> AppResult<Option<u16>> {
    match raw {
        None => Ok(None),
        Some(port) => {
            if !(1..=MAX_PORT).contains(&port) {
                return Err(AppError::invalid_input("Port must be between 1 and 65535."));
            }
            u16::try_from(port)
                .map(Some)
                .map_err(|_| AppError::invalid_input("Port must be between 1 and 65535."))
        }
    }
}

/// The schema/database name on the server.
pub fn validate_database_name(raw: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(
            "Database name contains characters that are not allowed.",
        ));
    }

    let name = raw.trim();

    if name.is_empty() {
        return Err(AppError::invalid_input("Database name is required."));
    }
    if name.chars().count() > MAX_DB_NAME_LEN {
        return Err(AppError::invalid_input(format!(
            "Database name must be {MAX_DB_NAME_LEN} characters or fewer."
        )));
    }

    let allowed = name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ' '));

    if !allowed || name.starts_with('.') || name.contains("..") {
        return Err(AppError::invalid_input(
            "Database name may only contain letters, numbers, spaces and _ - .",
        ));
    }

    Ok(name.to_string())
}

/// Optional database user name.
///
/// This is an *identifier*, not a secret. BackMeUp stores no password in this
/// phase at all, so there is no credential to protect here yet - see
/// `databases::CREDENTIAL_STORAGE_NOTE`.
pub fn validate_username(raw: &str) -> AppResult<Option<String>> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(
            "User name contains characters that are not allowed.",
        ));
    }

    let user = raw.trim();
    if user.is_empty() {
        return Ok(None);
    }
    if user.chars().count() > MAX_USERNAME_LEN {
        return Err(AppError::invalid_input("User name is too long."));
    }

    Ok(Some(user.to_string()))
}

/// A record identifier as produced by `util::random_id()`: exactly 64
/// lowercase hex characters.
///
/// This is the strongest possible constraint on an identifier arriving from
/// the webview and is applied to every id that is later bound into SQL.
pub fn validate_record_id(raw: &str) -> AppResult<()> {
    if raw.len() != 64 || !raw.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err(AppError::invalid_input("That record could not be found."));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SSH tunnel fields
// ---------------------------------------------------------------------------

/// The two SSH authentication methods this build understands.
pub const SSH_AUTH_PASSWORD: &str = "password";
pub const SSH_AUTH_PRIVATE_KEY: &str = "private_key";

/// Normalise an SSH host-key fingerprint.
///
/// Accepted forms: the bare SHA-256 digest in base64 (as produced by
/// `ssh::HostKeyInfo::fingerprint`) and OpenSSH's display form with a
/// `SHA256:` prefix. The normalised value that is stored and compared is
/// always the bare base64 digest.
pub fn validate_fingerprint(raw: &str) -> AppResult<String> {
    if crate::util::contains_control_chars(raw) {
        return Err(AppError::invalid_input(
            "That server fingerprint is not valid.",
        ));
    }

    let trimmed = raw.trim();
    let value = trimmed
        .strip_prefix("SHA256:")
        .or_else(|| trimmed.strip_prefix("sha256:"))
        .unwrap_or(trimmed)
        .trim();

    let base64_alphabet = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '='));

    // A SHA-256 digest is 43 base64 characters without padding, or 44 with a
    // single '=' terminator.
    let length_ok = value.len() == 43 || value.len() == 44;
    let padding_ok = match value.strip_suffix('=') {
        Some(body) => value.len() == 44 && !body.is_empty() && !body.contains('='),
        None => !value.contains('='),
    };

    if !base64_alphabet || !length_ok || !padding_ok {
        return Err(AppError::invalid_input(
            "Server fingerprints look like SHA256: followed by 43 base64 characters.",
        ));
    }

    Ok(value.to_string())
}

/// True for a dotted-quad IPv4 literal with four decimal octets in 0-255.
fn is_valid_ipv4(raw: &str) -> bool {
    let octets: Vec<&str> = raw.split('.').collect();
    octets.len() == 4
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && octet.len() <= 3
                && octet.chars().all(|c| c.is_ascii_digit())
                && octet.parse::<u16>().is_ok_and(|value| value <= 255)
        })
}

/// True for a textual IPv6 address without brackets.
///
/// Strict by construction: 1-8 hextets, at most one `::` compression group,
/// and an optional dotted-quad tail for the IPv4-mapped form. Nothing outside
/// hex digits and `:` can appear, so the value can never carry a separator,
/// a space or a traversal shape.
fn is_valid_ipv6(raw: &str) -> bool {
    if raw.is_empty() || raw.len() > 45 {
        return false;
    }

    let (head, tail) = match raw.split_once("::") {
        Some((head, tail)) => {
            // A second "::" would mean two compression groups.
            if tail.contains("::") {
                return false;
            }
            (head, Some(tail))
        }
        None => (raw, None),
    };

    let groups_are_valid = |part: &str| -> bool {
        if part.is_empty() {
            return true;
        }
        let groups: Vec<&str> = part.split(':').collect();
        groups.iter().enumerate().all(|(index, group)| {
            if group.contains('.') {
                // A dotted quad is only meaningful as the very last group.
                index == groups.len() - 1 && groups.len() > 1 && is_valid_ipv4(group)
            } else {
                !group.is_empty()
                    && group.len() <= 4
                    && group.chars().all(|c| c.is_ascii_hexdigit())
            }
        })
    };

    if !groups_are_valid(head) {
        return false;
    }

    match tail {
        Some(tail) => groups_are_valid(tail),
        // Without a compression group there must be all eight hextets.
        None => !head.is_empty() && head.split(':').count() == 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_reasonable_emails_and_normalises_case() {
        assert_eq!(validate_email(" Kent@Example.COM ").unwrap(), "kent@example.com");
        assert_eq!(
            validate_email("first.last+tag@sub.example.co.uk").unwrap(),
            "first.last+tag@sub.example.co.uk"
        );
    }

    #[test]
    fn rejects_malformed_emails() {
        for bad in [
            "",
            "plainaddress",
            "@example.com",
            "user@",
            "user@@example.com",
            "user@example",
            "user@-example.com",
            "user@example.c",
            "user@example.1a",
            "user name@example.com",
            "user@exa mple.com",
            "a..b@example.com",
        ] {
            assert!(validate_email(bad).is_err(), "expected rejection: {bad:?}");
        }
    }

    #[test]
    fn password_policy_is_enforced() {
        assert!(validate_password("Short-1-abc").is_err());
        assert!(validate_password("alllowercase-123!").is_err());
        assert!(validate_password("ALLUPPERCASE-123!").is_err());
        assert!(validate_password("NoDigitsHere!!!").is_err());
        assert!(validate_password("NoSymbolsHere123").is_err());
        assert!(validate_password("password12345").is_err());
        assert!(validate_password("Correct-Horse-9!").is_ok());
        assert!(validate_password(&"A1!".repeat(200)).is_err(), "too long");
    }

    #[test]
    fn confirmation_must_match() {
        assert!(validate_password_pair("Correct-Horse-9!", "Correct-Horse-9!").is_ok());
        assert!(validate_password_pair("Correct-Horse-9!", "Correct-Horse-8!").is_err());
    }

#[test]
    fn names_are_validated() {
        assert!(validate_full_name("  ").is_err());
        assert!(validate_full_name("K").is_err());
        assert!(validate_full_name(&"x".repeat(101)).is_err());
        assert!(validate_full_name("bad\u{0}name").is_err());
        assert_eq!(validate_full_name(" Kent Louise ").unwrap(), "Kent Louise");
    }

    #[test]
    fn hosts_accept_names_and_addresses_only() {
        assert_eq!(validate_host(" db.Example.COM ").unwrap(), "db.example.com");
        assert_eq!(validate_host("10.0.0.5").unwrap(), "10.0.0.5");

        for good in [
            "[::1]",
            "[::]",
            "[2001:db8::1]",
            "[::ffff:192.168.1.1]",
            "[2001:0db8:0000:0000:0000:0000:0000:0001]",
        ] {
            assert!(validate_host(good).is_ok(), "expected acceptance: {good:?}");
        }

        for bad in [
            "",
            "   ",
            "localhost; rm -rf /",
            "../etc/passwd",
            "host..name",
            ".host",
            "host-",
            "-host",
            "db.example.com/",
            "host name",
            "caf\u{e9}.example.com",
            "::1",                                  // bare IPv6 must be bracketed
            "[:1]",
            "[1:::2]",
            "[1::2::3]",
            "[12345::1]",
            "[gggg::1]",
            "[1:2:3:4:5:6:7]",                     // too few hextets, no compression
            "[1:2:3:4:5:6:7:8:9]",
            "[999.1.1.1::]",
            "[::1",
            &"h".repeat(254),
        ] {
            assert!(validate_host(bad).is_err(), "expected rejection: {bad:?}");
        }
    }

    #[test]
    fn ipv_literals_are_parsed_strictly() {
        assert!(is_valid_ipv4("192.168.1.1"));
        assert!(!is_valid_ipv4("256.0.0.1"));
        assert!(!is_valid_ipv4("1.2.3"));
        assert!(!is_valid_ipv4("1.2.3.4.5"));

        assert!(is_valid_ipv6("::1"));
        assert!(!is_valid_ipv6("1:2:3"));
        assert!(!is_valid_ipv6(""));
    }

    #[test]
    fn ports_are_range_checked_and_optional() {
        assert_eq!(validate_port(None).unwrap(), None);
        assert_eq!(validate_port(Some(3306)).unwrap(), Some(3306));
        assert_eq!(validate_port(Some(1)).unwrap(), Some(1));
        assert_eq!(validate_port(Some(65_535)).unwrap(), Some(65_535));
        for bad in [Some(0), Some(-1), Some(65_536), Some(i64::MAX)] {
            assert!(validate_port(bad).is_err(), "expected rejection: {bad:?}");
        }
    }

    #[test]
    fn database_names_use_a_strict_allowlist() {
        assert_eq!(validate_database_name(" shop_db ").unwrap(), "shop_db");
        assert_eq!(validate_database_name("my db.v2").unwrap(), "my db.v2");
        for bad in ["", "  ", "db;drop", "db\"quoted", "db\\name", ".hidden", "a..b", "db\u{0}x"] {
            assert!(validate_database_name(bad).is_err(), "expected rejection: {bad:?}");
        }
        assert!(validate_database_name(&"d".repeat(129)).is_err());
    }

    #[test]
    fn usernames_are_optional_but_bounded() {
        assert_eq!(validate_username("   ").unwrap(), None);
        assert_eq!(validate_username(" backup_admin ").unwrap(), Some("backup_admin".into()));
        assert!(validate_username("bad\u{0}user").is_err());
        assert!(validate_username(&"u".repeat(129)).is_err());
    }

    #[test]
    fn record_ids_must_be_random_hex() {
        assert!(validate_record_id(&"a".repeat(64)).is_ok());
        assert!(validate_record_id(&"0".repeat(64)).is_ok());

        for bad in [
            "".to_string(),
            "a".repeat(63),
            "a".repeat(65),
            "A".repeat(64),           // uppercase is not what random_id emits
            format!("{}!", "a".repeat(63)),
            "'; DROP TABLE backup_runs; --".to_string(),
            "../../windows/system32".to_string(),
        ] {
            assert!(validate_record_id(&bad).is_err(), "expected rejection: {bad:?}");
        }
    }

    #[test]
    fn fingerprints_normalise_to_the_bare_base64_digest() {
        let digest = format!("{}{}", "A".repeat(40), "bcd");
        assert_eq!(validate_fingerprint(&digest).unwrap(), digest);
        assert_eq!(
            validate_fingerprint(&format!("SHA256:{digest}")).unwrap(),
            digest,
            "the OpenSSH prefix is accepted and stripped"
        );
        assert_eq!(
            validate_fingerprint(&format!("sha256:{digest}")).unwrap(),
            digest
        );
        assert_eq!(
            validate_fingerprint(&format!("  SHA256: {digest}  ")).unwrap(),
            digest
        );

        // The padded form (44 characters ending in '=') is accepted unchanged.
        let padded = format!("{digest}=");
        assert_eq!(validate_fingerprint(&padded).unwrap(), padded);
    }

    #[test]
    fn malformed_fingerprints_are_refused() {
        for bad in [
            String::new(),
            "   ".to_string(),
            "SHA256:".to_string(),
            "A".repeat(42),
            "A".repeat(45),
            format!("{}=", "A".repeat(42)),      // two padding slots
            format!("{}=", "A".repeat(43)).replace("AAA", "A=A"),
            "uJwXkQz1a2B3c4D5e6F7g8H9i0J1k2L3m4N5o6P7!".to_string(),
            "<script>alert(1)</script>".to_string(),
            "SHA256:\u{0}AAAA".to_string(),
        ] {
            assert!(
                validate_fingerprint(&bad).is_err(),
                "expected rejection: {bad:?}"
            );
        }
    }

    #[test]
    fn labels_are_trimmed_and_bounded() {
        assert_eq!(validate_label("  Production  ", "Name").unwrap(), "Production");
        assert!(validate_label("   ", "Name").is_err());
        assert!(validate_label(&"n".repeat(101), "Name").is_err());
        assert!(validate_label("bad\nname", "Name").is_err());
    }
}
