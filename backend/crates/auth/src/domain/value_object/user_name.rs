//! User Name Value Object
//!
//! ユーザー名は、ユーザーを識別するための**公開識別子（ハンドル）**。
//! ログイン、画面表示、検索、管理運用に使用される。
//!
//! ## 設計方針
//! - ASCII文字のみ許可（a-z, 0-9, _ . - +）
//! - 大文字入力は受け付けるが、canonical（正規形）は小文字
//! - NFKC正規化 → 検証 → 小文字化 の順で処理
//! - 予約語チェックは設定可能（デフォルトリスト + 外部設定）
//!
//! ## 不変条件
//! - 長さ: 3〜30文字（正規化後）
//! - 先頭・末尾: 英数字または `_`
//! - 連続ドット禁止（`..`）
//! - 英数字を最低1文字含む（記号のみ禁止）
//! - 途中の空白禁止

use serde::{Deserialize, Serialize};
use std::fmt;
use unicode_normalization::UnicodeNormalization;

// ============================================================================
// Constants
// ============================================================================

/// Minimum length for user name (in characters)
pub const USER_NAME_MIN_LENGTH: usize = 3;

/// Maximum length for user name (in characters)
pub const USER_NAME_MAX_LENGTH: usize = 30;

/// Allowed special characters in user name
const ALLOWED_SPECIAL_CHARS: &[char] = &['_', '.', '-', '+'];

/// Default reserved words that cannot be used as user names
///
/// This list includes:
/// - System/Admin related terms
/// - API/Routing terms
/// - Authentication terms
/// - Common reserved terms
const DEFAULT_RESERVED_WORDS: &[&str] = &[
    // System/Admin
    "admin",
    "administrator",
    "root",
    "system",
    "sys",
    "superuser",
    "moderator",
    "mod",
    "staff",
    "support",
    "help",
    "helpdesk",
    // API/Routing
    "api",
    "graphql",
    "rest",
    "webhook",
    "webhooks",
    "callback",
    "oauth",
    "auth",
    "login",
    "logout",
    "signin",
    "signout",
    "signup",
    "register",
    "password",
    "reset",
    "verify",
    "confirm",
    "activate",
    "deactivate",
    // Resources
    "user",
    "users",
    "account",
    "accounts",
    "profile",
    "profiles",
    "settings",
    "config",
    "configuration",
    "dashboard",
    "home",
    "index",
    "main",
    // Common reserved
    "www",
    "mail",
    "email",
    "ftp",
    "ssh",
    "test",
    "demo",
    "example",
    "sample",
    "null",
    "undefined",
    "anonymous",
    "guest",
    "public",
    "private",
    "internal",
    "external",
    // Special
    "me",
    "self",
    "this",
    "new",
    "edit",
    "delete",
    "remove",
    "create",
    "update",
    "search",
    "find",
    "list",
    "all",
    "none",
    "true",
    "false",
    // Brand protection
    "official",
    "verified",
    "bot",
    "service",
];

// ============================================================================
// Error Types
// ============================================================================

/// Error returned when user name validation fails
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserNameError {
    /// User name is empty after normalization
    Empty,

    /// User name is too short (minimum: USER_NAME_MIN_LENGTH)
    TooShort { length: usize, min: usize },

    /// User name is too long (maximum: USER_NAME_MAX_LENGTH)
    TooLong { length: usize, max: usize },

    /// User name contains invalid character
    InvalidCharacter { char: char, position: usize },

    /// User name starts with invalid character (must be alphanumeric or _)
    InvalidStart { char: char },

    /// User name ends with invalid character (must be alphanumeric or _)
    InvalidEnd { char: char },

    /// User name contains consecutive dots (..)
    ConsecutiveDots,

    /// User name contains no alphanumeric characters
    NoAlphanumeric,

    /// User name contains whitespace in the middle
    ContainsWhitespace,

    /// User name is a reserved word
    Reserved { word: String },
}

impl fmt::Display for UserNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "User name cannot be empty"),
            Self::TooShort { length, min } => {
                write!(f, "User name is too short ({length} chars, minimum {min})")
            }
            Self::TooLong { length, max } => {
                write!(f, "User name is too long ({length} chars, maximum {max})")
            }
            Self::InvalidCharacter { char, position } => {
                write!(
                    f,
                    "Invalid character '{char}' at position {position}. Only a-z, 0-9, _, ., -, + are allowed"
                )
            }
            Self::InvalidStart { char } => {
                write!(
                    f,
                    "User name cannot start with '{char}'. Must start with a-z, 0-9, or _"
                )
            }
            Self::InvalidEnd { char } => {
                write!(
                    f,
                    "User name cannot end with '{char}'. Must end with a-z, 0-9, or _"
                )
            }
            Self::ConsecutiveDots => {
                write!(f, "User name cannot contain consecutive dots (..)")
            }
            Self::NoAlphanumeric => {
                write!(f, "User name must contain at least one letter or digit")
            }
            Self::ContainsWhitespace => {
                write!(f, "User name cannot contain whitespace")
            }
            Self::Reserved { word } => {
                write!(f, "'{word}' is a reserved user name")
            }
        }
    }
}

impl std::error::Error for UserNameError {}

// ============================================================================
// UserName Value Object
// ============================================================================

/// Validated, normalized user name
///
/// # Invariants
/// - Non-empty after normalization
/// - Length between USER_NAME_MIN_LENGTH and USER_NAME_MAX_LENGTH
/// - Contains only ASCII alphanumeric and allowed special characters
/// - Starts and ends with alphanumeric or underscore
/// - No consecutive dots
/// - Contains at least one alphanumeric character
/// - Not a reserved word
///
/// # Storage
/// - `original`: The user's input (trimmed, NFKC normalized, preserves case)
/// - `canonical`: Lowercase form for uniqueness checks
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct UserName {
    /// Original user input (preserves case)
    original: String,
    /// Canonical form (lowercase) for uniqueness
    canonical: String,
}

impl UserName {
    /// Create a new UserName from raw input
    ///
    /// Applies normalization (NFKC, trim) and validates.
    /// Preserves case in original, stores lowercase in canonical.
    pub fn new(
        input: impl AsRef<str>,
        reserved_words: Option<&[&str]>,
    ) -> Result<Self, UserNameError> {
        let reserved = reserved_words.unwrap_or(DEFAULT_RESERVED_WORDS);
        Self::new_with_reserved(input, reserved)
    }

    /// Create a new UserName with custom reserved words list
    ///
    /// Use this when you need to check against an external/configurable
    /// reserved words list.
    pub fn new_with_reserved(
        input: impl AsRef<str>,
        reserved_words: &[&str],
    ) -> Result<Self, UserNameError> {
        let original = Self::normalize_original(input.as_ref());
        let canonical = original.to_lowercase();
        Self::validate(&canonical, reserved_words)?;
        Ok(Self {
            original,
            canonical,
        })
    }

    /// Get the original user name (preserves case)
    #[inline]
    pub fn original(&self) -> &str {
        &self.original
    }

    /// Get the canonical (normalized, lowercase) user name
    #[inline]
    pub fn canonical(&self) -> &str {
        &self.canonical
    }

    /// Alias for canonical() for compatibility
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.canonical
    }

    /// Convert to owned String (canonical form)
    #[inline]
    pub fn into_inner(self) -> String {
        self.canonical
    }

    /// Create from database values (assumes already validated)
    pub fn from_db(original: &str) -> Result<Self, UserNameError> {
        let canonical = original.to_lowercase();
        Ok(Self {
            original: original.to_string(),
            canonical,
        })
    }

    /// Normalize input string (trim and NFKC, preserve case)
    fn normalize_original(input: &str) -> String {
        input.nfkc().collect::<String>().trim().to_string()
    }

    /// Normalize input string to canonical form (lowercase)
    fn normalize(input: &str) -> String {
        Self::normalize_original(input).to_lowercase()
    }

    /// Validate the normalized user name
    fn validate(canonical: &str, reserved_words: &[&str]) -> Result<(), UserNameError> {
        // Check empty
        if canonical.is_empty() {
            return Err(UserNameError::Empty);
        }

        // Check length
        let length = canonical.chars().count();
        if length < USER_NAME_MIN_LENGTH {
            return Err(UserNameError::TooShort {
                length,
                min: USER_NAME_MIN_LENGTH,
            });
        }
        if length > USER_NAME_MAX_LENGTH {
            return Err(UserNameError::TooLong {
                length,
                max: USER_NAME_MAX_LENGTH,
            });
        }

        // Check for whitespace anywhere
        if canonical.chars().any(|c| c.is_whitespace()) {
            return Err(UserNameError::ContainsWhitespace);
        }

        // Check all characters are valid
        for (pos, ch) in canonical.chars().enumerate() {
            if !Self::is_valid_char(ch) {
                return Err(UserNameError::InvalidCharacter {
                    char: ch,
                    position: pos,
                });
            }
        }

        // Check start character
        let first_char = canonical.chars().next().unwrap();
        if !Self::is_valid_start_end_char(first_char) {
            return Err(UserNameError::InvalidStart { char: first_char });
        }

        // Check end character
        let last_char = canonical.chars().next_back().unwrap();
        if !Self::is_valid_start_end_char(last_char) {
            return Err(UserNameError::InvalidEnd { char: last_char });
        }

        // Check consecutive dots
        if canonical.contains("..") {
            return Err(UserNameError::ConsecutiveDots);
        }

        // Check at least one alphanumeric
        if !canonical.chars().any(|c| c.is_ascii_alphanumeric()) {
            return Err(UserNameError::NoAlphanumeric);
        }

        // Check reserved words
        if reserved_words.iter().any(|&w| w == canonical) {
            return Err(UserNameError::Reserved {
                word: canonical.to_string(),
            });
        }

        Ok(())
    }

    /// Check if character is valid in a user name
    #[inline]
    fn is_valid_char(c: char) -> bool {
        c.is_ascii_lowercase() || c.is_ascii_digit() || ALLOWED_SPECIAL_CHARS.contains(&c)
    }

    /// Check if character is valid at start or end of user name
    #[inline]
    fn is_valid_start_end_char(c: char) -> bool {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
    }

    /// Get the default reserved words list
    pub fn default_reserved_words() -> &'static [&'static str] {
        DEFAULT_RESERVED_WORDS
    }

    /// Check if a string matches a reserved word
    pub fn is_reserved(name: &str) -> bool {
        let normalized = Self::normalize(name);
        DEFAULT_RESERVED_WORDS.iter().any(|&w| w == normalized)
    }
}

impl fmt::Debug for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserName")
            .field("original", &self.original)
            .field("canonical", &self.canonical)
            .finish()
    }
}

impl fmt::Display for UserName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.original)
    }
}

impl AsRef<str> for UserName {
    fn as_ref(&self) -> &str {
        &self.canonical
    }
}

impl TryFrom<String> for UserName {
    type Error = UserNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value, None)
    }
}

impl TryFrom<&str> for UserName {
    type Error = UserNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value, None)
    }
}

impl From<UserName> for String {
    fn from(name: UserName) -> Self {
        name.original
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    mod normalization {
        use super::*;

        #[test]
        fn test_trim_whitespace() {
            let name = UserName::new("  alice  ", None).unwrap();
            assert_eq!(name.as_str(), "alice");
        }

        #[test]
        fn test_lowercase() {
            let name = UserName::new("ALICE", None).unwrap();
            assert_eq!(name.as_str(), "alice");
        }

        #[test]
        fn test_mixed_case() {
            let name = UserName::new("AlIcE_123", None).unwrap();
            assert_eq!(name.as_str(), "alice_123");
        }

        #[test]
        fn test_nfkc_normalization() {
            // Full-width 'Ａ' (U+FF21) should normalize to 'a' (lowercase)
            let name = UserName::new("Ａlice", None);
            // Full-width characters become ASCII after NFKC
            assert!(name.is_ok());
            assert_eq!(name.unwrap().as_str(), "alice");
        }

        #[test]
        fn test_idempotent() {
            let input = "  AlIcE_123  ";
            let first = UserName::new(input, None).unwrap();
            let second = UserName::new(first.as_str(), None).unwrap();
            // canonical forms should be equal
            assert_eq!(first.canonical(), second.canonical());
        }
    }

    mod length_validation {
        use super::*;

        #[test]
        fn test_empty_fails() {
            assert!(matches!(UserName::new("", None), Err(UserNameError::Empty)));
        }

        #[test]
        fn test_whitespace_only_fails() {
            assert!(matches!(
                UserName::new("   ", None),
                Err(UserNameError::Empty)
            ));
        }

        #[test]
        fn test_too_short() {
            assert!(matches!(
                UserName::new("ab", None),
                Err(UserNameError::TooShort { length: 2, min: 3 })
            ));
        }

        #[test]
        fn test_minimum_length() {
            let name = UserName::new("abc", None);
            assert!(name.is_ok());
            assert_eq!(name.unwrap().as_str(), "abc");
        }

        #[test]
        fn test_maximum_length() {
            let input = "a".repeat(USER_NAME_MAX_LENGTH);
            let name = UserName::new(&input, None);
            assert!(name.is_ok());
        }

        #[test]
        fn test_too_long() {
            let input = "a".repeat(USER_NAME_MAX_LENGTH + 1);
            assert!(matches!(
                UserName::new(&input, None),
                Err(UserNameError::TooLong { .. })
            ));
        }
    }

    mod character_validation {
        use super::*;

        #[test]
        fn test_valid_alphanumeric() {
            assert!(UserName::new("alice123", None).is_ok());
        }

        #[test]
        fn test_valid_underscore() {
            assert!(UserName::new("alice_bob", None).is_ok());
        }

        #[test]
        fn test_valid_dot() {
            assert!(UserName::new("alice.bob", None).is_ok());
        }

        #[test]
        fn test_valid_hyphen() {
            assert!(UserName::new("alice-bob", None).is_ok());
        }

        #[test]
        fn test_valid_plus() {
            assert!(UserName::new("alice+tag", None).is_ok());
        }

        #[test]
        fn test_invalid_special_char() {
            assert!(matches!(
                UserName::new("alice@bob", None),
                Err(UserNameError::InvalidCharacter { char: '@', .. })
            ));
        }

        #[test]
        fn test_invalid_unicode() {
            // Japanese characters are not allowed
            assert!(matches!(
                UserName::new("日本語", None),
                Err(UserNameError::InvalidCharacter { .. })
            ));
        }

        #[test]
        fn test_invalid_emoji() {
            assert!(matches!(
                UserName::new("alice🎉", None),
                Err(UserNameError::InvalidCharacter { .. })
            ));
        }
    }

    mod position_validation {
        use super::*;

        #[test]
        fn test_start_with_letter() {
            assert!(UserName::new("alice", None).is_ok());
        }

        #[test]
        fn test_start_with_digit() {
            assert!(UserName::new("123alice", None).is_ok());
        }

        #[test]
        fn test_start_with_underscore() {
            assert!(UserName::new("_alice", None).is_ok());
        }

        #[test]
        fn test_start_with_dot_fails() {
            assert!(matches!(
                UserName::new(".alice", None),
                Err(UserNameError::InvalidStart { char: '.' })
            ));
        }

        #[test]
        fn test_start_with_hyphen_fails() {
            assert!(matches!(
                UserName::new("-alice", None),
                Err(UserNameError::InvalidStart { char: '-' })
            ));
        }

        #[test]
        fn test_start_with_plus_fails() {
            assert!(matches!(
                UserName::new("+alice", None),
                Err(UserNameError::InvalidStart { char: '+' })
            ));
        }

        #[test]
        fn test_end_with_letter() {
            assert!(UserName::new("alice", None).is_ok());
        }

        #[test]
        fn test_end_with_digit() {
            assert!(UserName::new("alice123", None).is_ok());
        }

        #[test]
        fn test_end_with_underscore() {
            assert!(UserName::new("alice_", None).is_ok());
        }

        #[test]
        fn test_end_with_dot_fails() {
            assert!(matches!(
                UserName::new("alice.", None),
                Err(UserNameError::InvalidEnd { char: '.' })
            ));
        }

        #[test]
        fn test_end_with_hyphen_fails() {
            assert!(matches!(
                UserName::new("alice-", None),
                Err(UserNameError::InvalidEnd { char: '-' })
            ));
        }

        #[test]
        fn test_end_with_plus_fails() {
            assert!(matches!(
                UserName::new("alice+", None),
                Err(UserNameError::InvalidEnd { char: '+' })
            ));
        }
    }

    mod pattern_validation {
        use super::*;

        #[test]
        fn test_consecutive_dots_fails() {
            assert!(matches!(
                UserName::new("alice..bob", None),
                Err(UserNameError::ConsecutiveDots)
            ));
        }

        #[test]
        fn test_single_dots_ok() {
            assert!(UserName::new("alice.bob.charlie", None).is_ok());
        }

        #[test]
        fn test_symbols_only_fails() {
            assert!(matches!(
                UserName::new("___", None),
                Err(UserNameError::NoAlphanumeric)
            ));
        }

        #[test]
        fn test_whitespace_in_middle_fails() {
            // Note: After NFKC normalization and trim, internal spaces remain
            // But they're not valid ASCII chars
            let result = UserName::new("alice bob", None);
            assert!(matches!(
                result,
                Err(UserNameError::ContainsWhitespace)
                    | Err(UserNameError::InvalidCharacter { .. })
            ));
        }
    }

    mod reserved_words {
        use super::*;

        #[test]
        fn test_reserved_admin() {
            assert!(matches!(
                UserName::new("admin", None),
                Err(UserNameError::Reserved { word }) if word == "admin"
            ));
        }

        #[test]
        fn test_reserved_case_insensitive() {
            assert!(matches!(
                UserName::new("ADMIN", None),
                Err(UserNameError::Reserved { word }) if word == "admin"
            ));
        }

        #[test]
        fn test_reserved_root() {
            assert!(matches!(
                UserName::new("root", None),
                Err(UserNameError::Reserved { .. })
            ));
        }

        #[test]
        fn test_reserved_api() {
            assert!(matches!(
                UserName::new("api", None),
                Err(UserNameError::Reserved { .. })
            ));
        }

        #[test]
        fn test_custom_reserved_list() {
            let custom = &["customword", "another"];
            // Default reserved word should not be blocked
            let result = UserName::new_with_reserved("admin", custom);
            assert!(result.is_ok());
            // Custom reserved word should be blocked
            let result = UserName::new_with_reserved("customword", custom);
            assert!(matches!(result, Err(UserNameError::Reserved { .. })));
        }

        #[test]
        fn test_is_reserved() {
            assert!(UserName::is_reserved("admin"));
            assert!(UserName::is_reserved("ADMIN"));
            assert!(!UserName::is_reserved("alice"));
        }
    }

    mod serialization {
        use super::*;

        #[test]
        fn test_serialize() {
            let name = UserName::new("alice", None).unwrap();
            let json = serde_json::to_string(&name).unwrap();
            assert_eq!(json, "\"alice\"");
        }

        #[test]
        fn test_deserialize() {
            let json = "\"alice\"";
            let name: UserName = serde_json::from_str(json).unwrap();
            assert_eq!(name.as_str(), "alice");
        }

        #[test]
        fn test_deserialize_with_normalization() {
            let json = "\"ALICE\"";
            let name: UserName = serde_json::from_str(json).unwrap();
            assert_eq!(name.as_str(), "alice");
        }

        #[test]
        fn test_deserialize_invalid() {
            let json = "\"ab\""; // too short
            let result: Result<UserName, _> = serde_json::from_str(json);
            assert!(result.is_err());
        }
    }

    mod display_and_debug {
        use super::*;

        #[test]
        fn test_display() {
            let name = UserName::new("alice", None).unwrap();
            assert_eq!(format!("{}", name), "alice");
        }

        #[test]
        fn test_debug() {
            let name = UserName::new("alice", None).unwrap();
            let debug = format!("{:?}", name);
            assert!(debug.contains("UserName"));
            assert!(debug.contains("alice"));
        }
    }

    mod conversions {
        use super::*;

        #[test]
        fn test_try_from_string() {
            let name: Result<UserName, _> = "alice".to_string().try_into();
            assert!(name.is_ok());
        }

        #[test]
        fn test_try_from_str() {
            let name: Result<UserName, _> = "alice".try_into();
            assert!(name.is_ok());
        }

        #[test]
        fn test_into_string() {
            let name = UserName::new("alice", None).unwrap();
            let s: String = name.into();
            assert_eq!(s, "alice");
        }

        #[test]
        fn test_as_ref() {
            let name = UserName::new("alice", None).unwrap();
            let s: &str = name.as_ref();
            assert_eq!(s, "alice");
        }
    }

    mod error_messages {
        use super::*;

        #[test]
        fn test_error_display() {
            let err = UserNameError::TooShort { length: 2, min: 3 };
            let msg = err.to_string();
            assert!(msg.contains("2") && msg.contains("3"));
        }
    }
}
