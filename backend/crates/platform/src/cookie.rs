//! Cookie Management Infrastructure
//!
//! Common cookie handling utilities and configuration.

use axum::http::{HeaderMap, HeaderValue, header};

/// SameSite policy for cookies
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SameSite {
    Strict,
    #[default]
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }
}

/// Cookie configuration
#[derive(Debug, Clone)]
pub struct CookieConfig {
    pub name: String,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: SameSite,
    pub path: String,
    pub max_age_secs: Option<i64>,
}

impl Default for CookieConfig {
    fn default() -> Self {
        Self {
            name: "session".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_age_secs: None,
        }
    }
}

impl CookieConfig {
    /// Build Set-Cookie header value
    pub fn build_set_cookie(&self, value: &str) -> String {
        let mut cookie = format!("{}={}", self.name, value);

        if self.http_only {
            cookie.push_str("; HttpOnly");
        }
        if self.secure {
            cookie.push_str("; Secure");
        }
        cookie.push_str(&format!("; SameSite={}", self.same_site.as_str()));
        cookie.push_str(&format!("; Path={}", self.path));

        if let Some(max_age) = self.max_age_secs {
            cookie.push_str(&format!("; Max-Age={}", max_age));
        }

        cookie
    }

    /// Build Set-Cookie header for deletion (expired)
    pub fn build_delete_cookie(&self) -> String {
        format!("{}=; HttpOnly; Path={}; Max-Age=0", self.name, self.path)
    }
}

/// Extract a cookie value from headers
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|cookie| {
            let (key, value) = cookie.trim().split_once('=')?;

            if key == name {
                Some(value.to_string())
            } else {
                None
            }
        })
}

/// Create a Set-Cookie header value
pub fn set_cookie_header(config: &CookieConfig, value: &str) -> HeaderValue {
    HeaderValue::from_str(&config.build_set_cookie(value))
        .unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cookie_config_build() {
        let config = CookieConfig {
            name: "test".to_string(),
            secure: true,
            http_only: true,
            same_site: SameSite::Lax,
            path: "/api".to_string(),
            max_age_secs: Some(3600),
        };

        let cookie = config.build_set_cookie("value123");
        assert!(cookie.contains("test=value123"));
        assert!(cookie.contains("HttpOnly"));
        assert!(cookie.contains("Secure"));
        assert!(cookie.contains("SameSite=Lax"));
        assert!(cookie.contains("Path=/api"));
        assert!(cookie.contains("Max-Age=3600"));
    }

    #[test]
    fn test_extract_cookie() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=bar; session=abc123; other=xyz"),
        );

        assert_eq!(
            extract_cookie(&headers, "session"),
            Some("abc123".to_string())
        );
        assert_eq!(extract_cookie(&headers, "foo"), Some("bar".to_string()));
        assert_eq!(extract_cookie(&headers, "missing"), None);
    }
}
