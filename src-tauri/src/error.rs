use serde::Serialize;

/// Structured, user-safe errors.
///
/// Errors that cross the Tauri IPC boundary must never contain stack traces,
/// SQL statements, internal file system paths, database messages or any
/// credential material. The internal cause is only ever written to the local
/// stderr log for the operator.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
}

impl AppError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self::new("invalid_input", message)
    }

    pub fn unauthorized() -> Self {
        Self::new("unauthorized", "Your session has ended. Please sign in again.")
    }

    pub fn rate_limited(retry_after_secs: u64) -> Self {
        Self::new(
            "rate_limited",
            format!(
                "Too many attempts. Please wait {} second(s) before trying again.",
                retry_after_secs
            ),
        )
    }

    pub fn internal() -> Self {
        Self::new(
            "internal_error",
            "Something went wrong. Please restart BackMeUp and try again.",
        )
    }
}

impl std::fmt::Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AppError {}

impl From<rusqlite::Error> for AppError {
    fn from(err: rusqlite::Error) -> Self {
        eprintln!("[backmeup] database error: {err}");
        AppError::internal()
    }
}

impl From<argon2::password_hash::Error> for AppError {
    fn from(err: argon2::password_hash::Error) -> Self {
        eprintln!("[backmeup] password hashing error: {err}");
        AppError::internal()
    }
}

impl From<argon2::Error> for AppError {
    fn from(err: argon2::Error) -> Self {
        eprintln!("[backmeup] argon2 configuration error: {err}");
        AppError::internal()
    }
}

impl From<getrandom::Error> for AppError {
    fn from(err: getrandom::Error) -> Self {
        eprintln!("[backmeup] secure random source failure: {err}");
        AppError::new(
            "internal_error",
            "BackMeUp could not read from the operating system random source.",
        )
    }
}

pub type AppResult<T> = Result<T, AppError>;