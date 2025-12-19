//! Application Error - Unified error type for the application
//!
//! Defines [`AppError`] struct and [`AppResult<T>`] type alias.

use std::borrow::Cow;
use std::error::Error;
use std::fmt;

use super::kind::ErrorKind;

/// アプリケーション統一エラー型
///
/// プロジェクト全体で使用する標準エラー型です。
/// ビルダーパターンを使用してエラーを構築できます。
///
/// ## Fields
/// * `kind` - エラーの分類（HTTP ステータスコードにマッピング）
/// * `message` - ユーザー向けのエラーメッセージ
/// * `action` - ユーザーが取るべきアクション（オプション）
/// * `source` - 元のエラー（オプション、デバッグ用）
///
/// ## Examples
/// ```rust
/// use kernel::error::{app_error::AppError, kind::ErrorKind};
///
/// // シンプルなエラー
/// let err = AppError::new(ErrorKind::NotFound, "User not found");
///
/// // 詳細なエラー
/// let err = AppError::new(ErrorKind::BadRequest, "Invalid email format")
///     .with_action("Please enter a valid email address");
/// ```
pub struct AppError {
    /// エラー種別
    kind: ErrorKind,
    /// ユーザー向けメッセージ
    message: Cow<'static, str>,
    /// ユーザーが取るべきアクション
    action: Option<Cow<'static, str>>,
    /// 元のエラー（デバッグ用）
    source: Option<Box<dyn Error + Send + Sync + 'static>>,
}

/// アプリケーション結果型エイリアス
///
/// `Result<T, AppError>` の省略形です。
///
/// ## Examples
/// ```rust
/// use kernel::error::{app_error::{AppError, AppResult}, kind::ErrorKind};
///
/// fn find_user(id: u32) -> AppResult<String> {
///     if id == 0 {
///         return Err(AppError::not_found("User not found"));
///     }
///     Ok("Alice".to_string())
/// }
/// ```
pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    // ========================================================================
    // Constructors
    // ========================================================================

    /// 新しいエラーを作成
    ///
    /// ## Arguments
    /// * `kind` - エラー種別
    /// * `message` - ユーザー向けメッセージ
    ///
    /// ## Examples
    /// ```rust
    /// use kernel::error::{app_error::AppError, kind::ErrorKind};
    /// let err = AppError::new(ErrorKind::BadRequest, "Invalid input");
    /// ```
    #[inline]
    pub fn new(kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> Self {
        Self {
            kind,
            message: message.into(),
            action: None,
            source: None,
        }
    }

    // ========================================================================
    // Convenience constructors
    // ========================================================================

    /// 400 Bad Request エラー
    #[inline]
    pub fn bad_request(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::BadRequest, message)
    }

    /// 401 Unauthorized エラー
    #[inline]
    pub fn unauthorized(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::Unauthorized, message)
    }

    /// 403 Forbidden エラー
    #[inline]
    pub fn forbidden(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::Forbidden, message)
    }

    /// 404 Not Found エラー
    #[inline]
    pub fn not_found(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::NotFound, message)
    }

    /// 409 Conflict エラー
    #[inline]
    pub fn conflict(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::Conflict, message)
    }

    /// 410 Gone エラー
    #[inline]
    pub fn gone(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::Gone, message)
    }

    /// 422 Unprocessable Entity エラー
    #[inline]
    pub fn unprocessable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::UnprocessableEntity, message)
    }

    /// 429 Too Many Requests エラー
    #[inline]
    pub fn too_many_requests(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::TooManyRequests, message)
    }

    /// 500 Internal Server Error
    #[inline]
    pub fn internal(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::InternalServerError, message)
    }

    /// 503 Service Unavailable エラー
    #[inline]
    pub fn service_unavailable(message: impl Into<Cow<'static, str>>) -> Self {
        Self::new(ErrorKind::ServiceUnavailable, message)
    }

    // ========================================================================
    // Builder methods
    // ========================================================================

    /// ユーザー向けアクションを設定
    ///
    /// ## Arguments
    /// * `action` - ユーザーが取るべきアクション
    ///
    /// ## Examples
    /// ```rust
    /// use kernel::error::{app_error::AppError, kind::ErrorKind};
    /// let err = AppError::not_found("Session not found")
    ///     .with_action("Please try again");
    /// ```
    #[inline]
    pub fn with_action(mut self, action: impl Into<Cow<'static, str>>) -> Self {
        self.action = Some(action.into());
        self
    }

    /// 元のエラーを設定（デバッグ用）
    ///
    /// ## Arguments
    /// * `source` - 元のエラー
    ///
    /// ## Examples
    /// ```rust
    /// use kernel::error::{app_error::{AppError, AppResult}, kind::ErrorKind};
    /// use std::io;
    ///
    /// fn read_config() -> AppResult<()> {
    ///     std::fs::read_to_string("config.json")
    ///         .map_err(|e| AppError::internal("Failed to read config").with_source(e))?;
    ///     Ok(())
    /// }
    /// ```
    #[inline]
    pub fn with_source<E>(mut self, source: E) -> Self
    where
        E: Error + Send + Sync + 'static,
    {
        self.source = Some(Box::new(source));
        self
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// エラー種別を取得
    #[inline]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// HTTP ステータスコードを取得
    #[inline]
    pub fn status_code(&self) -> u16 {
        self.kind.status_code()
    }

    /// メッセージを取得
    #[inline]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// アクションを取得
    #[inline]
    pub fn action(&self) -> Option<&str> {
        self.action.as_deref()
    }

    /// サーバーエラーかどうか
    #[inline]
    pub fn is_server_error(&self) -> bool {
        self.kind.is_server_error()
    }

    /// クライアントエラーかどうか
    #[inline]
    pub fn is_client_error(&self) -> bool {
        self.kind.is_client_error()
    }
}

impl fmt::Debug for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut builder = f.debug_struct("AppError");
        builder.field("kind", &self.kind);
        builder.field("message", &self.message);
        if let Some(action) = &self.action {
            builder.field("action", action);
        }
        if let Some(source) = &self.source {
            builder.field("source", source);
        }
        builder.finish()
    }
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.kind, self.message)?;
        if let Some(action) = &self.action {
            write!(f, " (Action: {})", action)?;
        }
        Ok(())
    }
}

impl Error for AppError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source
            .as_ref()
            .map(|e| e.as_ref() as &(dyn Error + 'static))
    }
}

// ============================================================================
// Result extension traits
// ============================================================================

/// `Result<T, E>` を `AppResult<T>` に変換するための拡張トレイト
pub trait ResultExt<T, E> {
    /// エラーを `AppError` に変換し、指定した種別とメッセージでラップ
    fn map_app_err(self, kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> AppResult<T>
    where
        E: Error + Send + Sync + 'static;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn map_app_err(self, kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> AppResult<T>
    where
        E: Error + Send + Sync + 'static,
    {
        self.map_err(|e| AppError::new(kind, message).with_source(e))
    }
}

/// `Option<T>` を `AppResult<T>` に変換するための拡張トレイト
pub trait OptionExt<T> {
    /// `None` の場合に `AppError` を返す
    fn ok_or_app_err(self, kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> AppResult<T>;

    /// `None` の場合に 404 Not Found を返す
    fn ok_or_not_found(self, message: impl Into<Cow<'static, str>>) -> AppResult<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_app_err(self, kind: ErrorKind, message: impl Into<Cow<'static, str>>) -> AppResult<T> {
        self.ok_or_else(|| AppError::new(kind, message))
    }

    fn ok_or_not_found(self, message: impl Into<Cow<'static, str>>) -> AppResult<T> {
        self.ok_or_app_err(ErrorKind::NotFound, message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_error() {
        let err = AppError::new(ErrorKind::NotFound, "User not found");
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(err.status_code(), 404);
        assert_eq!(err.message(), "User not found");
        assert!(err.action().is_none());
    }

    #[test]
    fn test_convenience_constructors() {
        assert_eq!(AppError::bad_request("test").status_code(), 400);
        assert_eq!(AppError::unauthorized("test").status_code(), 401);
        assert_eq!(AppError::forbidden("test").status_code(), 403);
        assert_eq!(AppError::not_found("test").status_code(), 404);
        assert_eq!(AppError::conflict("test").status_code(), 409);
        assert_eq!(AppError::gone("test").status_code(), 410);
        assert_eq!(AppError::unprocessable("test").status_code(), 422);
        assert_eq!(AppError::too_many_requests("test").status_code(), 429);
        assert_eq!(AppError::internal("test").status_code(), 500);
        assert_eq!(AppError::service_unavailable("test").status_code(), 503);
    }

    #[test]
    fn test_with_action() {
        let err = AppError::not_found("Session not found").with_action("Please try again");
        assert_eq!(err.action(), Some("Please try again"));
    }

    #[test]
    fn test_with_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AppError::internal("Failed to read file").with_source(io_err);
        assert!(err.source().is_some());
    }

    #[test]
    fn test_display() {
        let err = AppError::not_found("User not found");
        assert_eq!(err.to_string(), "[Not Found] User not found");

        let err_with_action =
            AppError::bad_request("Invalid email").with_action("Enter valid email");
        assert!(err_with_action.to_string().contains("Action:"));
    }

    #[test]
    fn test_is_server_error() {
        assert!(!AppError::not_found("test").is_server_error());
        assert!(AppError::internal("test").is_server_error());
    }

    #[test]
    fn test_result_ext() {
        let result: Result<i32, std::io::Error> = Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "not found",
        ));
        let app_result = result.map_app_err(ErrorKind::NotFound, "Resource not found");
        assert!(app_result.is_err());
        assert_eq!(app_result.unwrap_err().status_code(), 404);
    }

    #[test]
    fn test_option_ext() {
        let none: Option<i32> = None;
        let result = none.ok_or_not_found("Item not found");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().status_code(), 404);

        let some: Option<i32> = Some(42);
        let result = some.ok_or_not_found("Item not found");
        assert_eq!(result.unwrap(), 42);
    }
}
