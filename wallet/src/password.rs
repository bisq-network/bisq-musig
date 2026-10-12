//! The wallet password as a type.
//!
//! A [`Password`] can only be built from a string that satisfies the password rules in
//! [`Password::PATTERN`], so every API taking one gets the rules for free: there is no way to
//! create or re-key a wallet with an empty or otherwise unacceptable password.

use std::fmt;
use std::str::FromStr;
use std::sync::LazyLock;

use fancy_regex::Regex;
use thiserror::Error;
use zeroize::Zeroizing;

/// A password that satisfies the wallet's password rules.
///
/// Nothing but the password string, but only obtainable through [`Password::check`] or
/// [`Password::new`] (or `str::parse`), which check the string against [`Password::PATTERN`] and
/// reject it otherwise. Holding a `Password` is therefore proof that the rules hold, and
/// the wallet API deals in nothing else: creating a wallet, opening it, checking or changing its
/// password all take a `Password`. Since every password in force passed the rules, an *attempt*
/// at an existing wallet's password that breaks them cannot be the right one, so callers taking
/// attempts from a user are free to report such a rejection as a wrong password rather than as
/// a weak one.
///
/// The plaintext is wiped from memory on drop and never shows up in `Debug` output.
pub struct Password(Zeroizing<String>);

/// A candidate password that breaks the wallet's password rules.
///
/// Its message is [`Password::REQUIREMENTS`], the rules in plain English, meant to be shown to the
/// user as is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{}", Password::REQUIREMENTS)]
pub struct WeakPassword;

/// An attempt at the password in force that is not that password.
///
/// [`Password::check`] returns it for an attempt that cannot be right because it breaks the
/// password rules; callers comparing an attempt against a wallet's password report a mismatch
/// the same way, so a user entering a password gets one answer for every wrong attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid wallet password")]
pub struct InvalidPassword;

static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(Password::PATTERN).expect("the password pattern is a valid regular expression")
});

impl Password {
    /// The password rules as a regular expression: at least 8 characters, among them at least one
    /// lowercase letter, one uppercase letter, one decimal digit and one character that is
    /// neither letter nor digit. Letters and digits are Unicode-aware (`\p{Ll}`, `\p{Lu}`,
    /// `\p{Nd}`), and a letter of a script without case (`\p{Lo}`: Chinese, Japanese, Korean,
    /// Arabic, Hebrew, Thai, …) counts as both lowercase and uppercase, so a password in any
    /// script qualifies. The lookaheads keep the pattern portable, e.g. Java's `Pattern`
    /// understands it as is, so a client can check a password before sending it.
    ///
    /// [`Self::REQUIREMENTS`] states the same rules in plain English; keep the two in step.
    pub const PATTERN: &'static str =
        r"^(?=.*[\p{Ll}\p{Lo}])(?=.*[\p{Lu}\p{Lo}])(?=.*\p{Nd})(?=.*[^\p{L}\p{Nd}]).{8,}$";

    /// [`Self::PATTERN`] in plain English, for the user whose password was rejected.
    pub const REQUIREMENTS: &'static str = "The password must be at least 8 characters long and \
        contain at least one lowercase letter, one uppercase letter, one number and one special \
        character (any character that is neither a letter nor a number, such as ! ? # or %). A \
        letter of a script without upper- and lowercase, such as Chinese or Arabic, counts as \
        both.";

    /// Checks an *attempt* at a password in force, as entered by a user proving they know it,
    /// against [`Self::PATTERN`] and wraps it.
    ///
    /// Every password in force passed the rules when it was set, so an attempt that breaks them
    /// cannot be right. It is rejected as [`InvalidPassword`], the answer any wrong attempt gets,
    /// rather than as [`WeakPassword`]: the user is entering a password, not choosing one.
    ///
    /// An owned string is moved in, so a rejected candidate is wiped from memory just like an
    /// accepted one is when dropped; a borrowed one is copied.
    pub fn check(attempt: impl Into<String>) -> Result<Self, InvalidPassword> {
        let attempt = Self(Zeroizing::new(attempt.into()));
        // `is_match` can only fail by exceeding the backtracking limit, which the pattern's
        // linear lookaheads make unreachable for anything but absurdly long input. Counting
        // that as a rejection beats panicking on user input.
        if matches!(PATTERN.is_match(attempt.as_str()), Ok(true)) {
            Ok(attempt)
        } else {
            Err(InvalidPassword)
        }
    }

    /// Checks a password about to be *set*, as chosen by a user, against [`Self::PATTERN`] and
    /// wraps it.
    ///
    /// The same check as [`Self::check`], but a rejection is a [`WeakPassword`], whose message
    /// tells the user how to make an acceptable password.
    pub fn new(password: impl Into<String>) -> Result<Self, WeakPassword> {
        Self::check(password).map_err(|_: InvalidPassword| WeakPassword)
    }

    /// The plaintext, for deriving the database key and nothing else, hence crate-private.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for Password {
    type Err = WeakPassword;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Password(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_password_that_follows_the_rules() {
        for candidate in [
            "Passw0rd!",
            "aB3$aB3$",
            "Correct Horse 9!",
            "Straße-2024",
            "Пароль#2024",
        ] {
            assert!(
                candidate.parse::<Password>().is_ok(),
                "{candidate:?} should be accepted"
            );
        }
    }

    #[test]
    fn rejects_a_password_that_breaks_a_rule() {
        for (candidate, broken_rule) in [
            ("", "empty"),
            ("Pw#1234", "only 7 characters"),
            ("passw0rd!", "no uppercase letter"),
            ("PASSW0RD!", "no lowercase letter"),
            ("Password!", "no number"),
            ("Passw0rd1", "no special character"),
        ] {
            assert_eq!(
                candidate.parse::<Password>().unwrap_err(),
                WeakPassword,
                "{candidate:?} should be rejected: {broken_rule}"
            );
        }
    }

    #[test]
    fn a_script_without_case_needs_no_case_variety() {
        for candidate in [
            "密码密码密码1!",
            "パスワード#2024",
            "كلمة-السر-2024",
            "รหัสผ่าน#2024",
        ] {
            assert!(
                candidate.parse::<Password>().is_ok(),
                "{candidate:?} should be accepted"
            );
        }
        // The other rules still apply.
        for (candidate, broken_rule) in [
            ("密码1!", "only 4 characters"),
            ("密码密码密码!!", "no number"),
            ("密码密码密码12", "no special character"),
        ] {
            assert_eq!(
                candidate.parse::<Password>().unwrap_err(),
                WeakPassword,
                "{candidate:?} should be rejected: {broken_rule}"
            );
        }
    }

    #[test]
    fn an_attempt_breaking_the_rules_is_simply_invalid() {
        assert!(Password::check("Passw0rd!").is_ok());
        for attempt in ["", "short", "wrong"] {
            assert_eq!(
                Password::check(attempt).unwrap_err(),
                InvalidPassword,
                "{attempt:?} can be no password in force"
            );
        }
    }

    #[test]
    fn rejection_explains_the_rules_in_plain_english() {
        let message = Password::new("").unwrap_err().to_string();
        assert_eq!(message, Password::REQUIREMENTS);
        assert!(message.contains("at least 8 characters"));
        assert!(
            !message.contains('\\') && !message.contains("(?="),
            "no regex syntax in the user-facing message: {message}"
        );
    }

    #[test]
    fn debug_output_hides_the_plaintext() {
        let password: Password = "Passw0rd!".parse().unwrap();
        let debug = format!("{password:?}");
        assert!(!debug.contains("Passw0rd"), "got: {debug}");
    }
}
