use std::collections::HashMap;
use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

/// Authenticated sessions live in Rust memory only.
///
/// There is deliberately no persisted "logged in" flag: closing and reopening
/// BackMeUp always requires a fresh login. The frontend never receives a
/// session token, so there is no token to steal from the webview.
#[derive(Clone)]
pub struct Session {
    pub owner_id: i64,
    pub email: String,
    pub created_at: Instant,
    pub last_activity: Instant,
}

/// Absolute lifetime of a session, independent of inactivity.
const SESSION_TTL: Duration = Duration::from_secs(60 * 60);
/// Idle timeout: the owner is asked to sign in again after this long without
/// any successful command.
const SESSION_IDLE_TTL: Duration = Duration::from_secs(30 * 60);

#[derive(Default)]
pub struct AuthState {
    session: Option<Session>,
    /// Plaintext recovery codes awaiting a "I saved them" confirmation. Held in
    /// memory only and zeroized as soon as they are confirmed or replaced.
    pending_codes: Option<Zeroizing<String>>,
    login_throttle: HashMap<String, Throttle>,
    global_login_throttle: Throttle,
    recovery_throttle: Throttle,
    /// Bounds how often a signed-in owner may attempt a database connection
    /// test.
    ///
    /// Without this a compromised webview could turn the test command into a
    /// port scanner against whatever the machine can reach. It reuses the same
    /// escalating cooldown as the login limiter.
    connection_test_throttle: Throttle,
    setup_gate: bool,
}

impl AuthState {
    /// Create a new session. Any previous session is discarded first, which
    /// prevents session fixation across logins.
    pub fn start_session(&mut self, owner_id: i64, email: String) {
        let now = Instant::now();
        self.session = Some(Session {
            owner_id,

            email,
            created_at: now,
            last_activity: now,
        });
    }

    pub fn end_session(&mut self) {
        self.session = None;
        self.clear_pending_codes();
    }

    /// Invalidate every session. Used after a password change or recovery so
    /// that a stolen or leftover authenticated context cannot survive.
    pub fn invalidate_all_sessions(&mut self) {
        self.end_session();
    }

    /// Read the current session without refreshing the idle timer. Used by
    /// read-only surfaces such as the bootstrap state.
    pub fn peek_session(&self) -> Option<&Session> {
        let now = Instant::now();
        let session = self.session.as_ref()?;

        if now.duration_since(session.created_at) > SESSION_TTL
            || now.duration_since(session.last_activity) > SESSION_IDLE_TTL
        {
            return None;
        }

        Some(session)
    }

    /// Return the current session if it is still valid, refreshing its idle timer
    /// as a side effect. Both the absolute lifetime and the idle timeout are
    /// enforced here, in the backend, for every privileged command.
    pub fn current_session(&mut self) -> Option<Session> {
        if self.peek_session().is_none() {
            self.session = None;
            return None;
        }

        if let Some(session) = self.session.as_mut() {
            session.last_activity = Instant::now();
            return Some(session.clone());
        }
        None
    }

    pub fn store_pending_codes(&mut self, codes: &[String]) {
        self.pending_codes = Some(Zeroizing::new(codes.join("\n")));
    }

    pub fn pending_codes(&self) -> Option<String> {
        self.pending_codes.as_ref().map(|c| c.to_string())
    }

    pub fn clear_pending_codes(&mut self) {
        if let Some(mut codes) = self.pending_codes.take() {
            codes.zeroize();
        }
    }

    /// Serialise first-run initialisation inside this process. The database
    /// unique constraints remain the authoritative cross-check.
    pub fn try_lock_setup(&mut self) -> bool {
        if self.setup_gate {
            return false;
        }
        self.setup_gate = true;
        true
    }

    pub fn unlock_setup(&mut self) {
        self.setup_gate = false;
    }

    pub fn login_throttle_mut(&mut self) -> &mut HashMap<String, Throttle> {
        &mut self.login_throttle
    }

    pub fn global_login_throttle_mut(&mut self) -> &mut Throttle {
        &mut self.global_login_throttle
    }

    pub fn recovery_throttle_mut(&mut self) -> &mut Throttle {
        &mut self.recovery_throttle
    }

    pub fn connection_test_throttle_mut(&mut self) -> &mut Throttle {
        &mut self.connection_test_throttle
    }

    /// Clear the connection-test cooldown after a successful sign-in, so a
    /// legitimate owner who tripped the limit is not penalised forever.
    pub fn reset_connection_test_throttle(&mut self) {
        self.connection_test_throttle.reset();
    }
}

/// Sliding-window failure tracker with an escalating cooldown.
///
/// Lockouts are always temporary: a correct credential is never permanently
/// blocked, the cooldown simply doubles up to a bounded ceiling.
#[derive(Default)]
pub struct Throttle {
    failures: Vec<Instant>,
    cooldown_until: Option<Instant>,
    penalty_secs: u64,
}

impl Throttle {
    /// Register a failure and return how long the caller must now wait.
    pub fn register_failure(
        &mut self,
        threshold: usize,
        window: Duration,
        base_penalty: Duration,
        max_penalty: Duration,
    ) -> Duration {
        let now = Instant::now();
        self.failures.retain(|t| now.duration_since(*t) < window);
        self.failures.push(now);

        if self.failures.len() >= threshold {
            let penalty = if self.penalty_secs == 0 {
                base_penalty.as_secs()
            } else {
                (self.penalty_secs * 2).min(max_penalty.as_secs())
            };
            self.penalty_secs = penalty;
            let until = now + Duration::from_secs(penalty);
            self.cooldown_until = Some(until);
            self.failures.clear();
            return Duration::from_secs(penalty);
        }

        Duration::ZERO
    }

    /// Remaining cooldown, or zero when the caller may proceed.
    pub fn remaining_lockout(&self) -> Duration {
        match self.cooldown_until {
            Some(until) => {
                let now = Instant::now();
                if now < until {
                    until - now
                } else {
                    Duration::ZERO
                }
            }
            None => Duration::ZERO,
        }
    }

    pub fn reset(&mut self) {
        self.failures.clear();
        self.cooldown_until = None;
        self.penalty_secs = 0;
    }

    /// True when the throttle carries no state and can be discarded.
    pub fn is_idle(&self) -> bool {
        self.failures.is_empty() && self.cooldown_until.is_none()
    }
}