//! Error Kind - Classification of errors
//!
//! Defines the [`ErrorKind`] enum that maps to HTTP status codes.

use serde::Serialize;

/// エラー種別の列挙体
///
/// HTTP ステータスコードに対応するエラー分類を定義します。
/// 各バリアントは RFC 7231/9110 に準拠したステータスコードにマッピングされます。
///
/// ## Notes
/// * `non_exhaustive` - 将来的に列挙子が追加される可能性があることを示す
///
/// ## Examples
/// ```rust
/// use kernel::error::kind::ErrorKind;
///
/// let kind = ErrorKind::NotFound;
/// assert_eq!(kind.status_code(), 404);
/// assert_eq!(kind.as_str(), "Not Found");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[non_exhaustive]
pub enum ErrorKind {
    /// 400 - Bad Request: リクエストが不正
    BadRequest,
    /// 401 - Unauthorized: 認証が必要
    Unauthorized,
    /// 403 - Forbidden: アクセス権限なし
    Forbidden,
    /// 404 - Not Found: リソースが見つからない
    NotFound,
    /// 408 - Request Timeout: リクエストタイムアウト
    RequestTimeout,
    /// 409 - Conflict: 現在の状態と競合
    Conflict,
    /// 410 - Gone: リソースが削除された/期限切れ
    Gone,
    /// 422 - Unprocessable Entity: 処理不可能なエンティティ
    UnprocessableEntity,
    /// 429 - Too Many Requests: レート制限超過
    TooManyRequests,
    /// 451 - Unavailable For Legal Reasons: 法的理由により利用不可
    UnavailableForLegalReasons,
    /// 500 - Internal Server Error: サーバー内部エラー
    InternalServerError,
    /// 503 - Service Unavailable: サービス利用不可
    ServiceUnavailable,
}

impl ErrorKind {
    /// HTTP ステータスコードを取得
    ///
    /// ## Returns
    /// RFC 7231/9110 に準拠した HTTP ステータスコード
    ///
    /// ## Examples
    /// ```rust
    /// use kernel::error::kind::ErrorKind;
    /// assert_eq!(ErrorKind::BadRequest.status_code(), 400);
    /// assert_eq!(ErrorKind::NotFound.status_code(), 404);
    /// ```
    #[inline]
    pub const fn status_code(&self) -> u16 {
        match self {
            ErrorKind::BadRequest => 400,
            ErrorKind::Unauthorized => 401,
            ErrorKind::Forbidden => 403,
            ErrorKind::NotFound => 404,
            ErrorKind::RequestTimeout => 408,
            ErrorKind::Conflict => 409,
            ErrorKind::Gone => 410,
            ErrorKind::UnprocessableEntity => 422,
            ErrorKind::TooManyRequests => 429,
            ErrorKind::UnavailableForLegalReasons => 451,
            ErrorKind::InternalServerError => 500,
            ErrorKind::ServiceUnavailable => 503,
        }
    }

    /// ユーザー向けの文字列表現を取得
    ///
    /// ## Returns
    /// HTTP ステータスの標準的な理由フレーズ
    ///
    /// ## Examples
    /// ```rust
    /// use kernel::error::kind::ErrorKind;
    /// assert_eq!(ErrorKind::BadRequest.as_str(), "Bad Request");
    /// ```
    #[inline]
    pub const fn as_str(&self) -> &'static str {
        match self {
            ErrorKind::BadRequest => "Bad Request",
            ErrorKind::Unauthorized => "Unauthorized",
            ErrorKind::Forbidden => "Forbidden",
            ErrorKind::NotFound => "Not Found",
            ErrorKind::RequestTimeout => "Request Timeout",
            ErrorKind::Conflict => "Conflict",
            ErrorKind::Gone => "Gone",
            ErrorKind::UnprocessableEntity => "Unprocessable Entity",
            ErrorKind::TooManyRequests => "Too Many Requests",
            ErrorKind::UnavailableForLegalReasons => "Unavailable For Legal Reasons",
            ErrorKind::InternalServerError => "Internal Server Error",
            ErrorKind::ServiceUnavailable => "Service Unavailable",
        }
    }

    /// サーバー側のエラーかどうかを判定
    ///
    /// 5xx系のエラーは `true` を返します。
    /// これらのエラーはログに記録すべきです。
    #[inline]
    pub const fn is_server_error(&self) -> bool {
        self.status_code() >= 500
    }

    /// クライアント側のエラーかどうかを判定
    ///
    /// 4xx系のエラーは `true` を返します。
    #[inline]
    pub const fn is_client_error(&self) -> bool {
        let code = self.status_code();
        code >= 400 && code < 500
    }
}

impl std::fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_codes() {
        assert_eq!(ErrorKind::BadRequest.status_code(), 400);
        assert_eq!(ErrorKind::Unauthorized.status_code(), 401);
        assert_eq!(ErrorKind::Forbidden.status_code(), 403);
        assert_eq!(ErrorKind::NotFound.status_code(), 404);
        assert_eq!(ErrorKind::RequestTimeout.status_code(), 408);
        assert_eq!(ErrorKind::Conflict.status_code(), 409);
        assert_eq!(ErrorKind::Gone.status_code(), 410);
        assert_eq!(ErrorKind::UnprocessableEntity.status_code(), 422);
        assert_eq!(ErrorKind::TooManyRequests.status_code(), 429);
        assert_eq!(ErrorKind::UnavailableForLegalReasons.status_code(), 451);
        assert_eq!(ErrorKind::InternalServerError.status_code(), 500);
        assert_eq!(ErrorKind::ServiceUnavailable.status_code(), 503);
    }

    #[test]
    fn test_is_server_error() {
        assert!(!ErrorKind::BadRequest.is_server_error());
        assert!(!ErrorKind::NotFound.is_server_error());
        assert!(ErrorKind::InternalServerError.is_server_error());
        assert!(ErrorKind::ServiceUnavailable.is_server_error());
    }

    #[test]
    fn test_is_client_error() {
        assert!(ErrorKind::BadRequest.is_client_error());
        assert!(ErrorKind::NotFound.is_client_error());
        assert!(!ErrorKind::InternalServerError.is_client_error());
    }
}
