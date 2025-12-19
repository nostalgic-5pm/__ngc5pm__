//! API Server Entry Point
//!
//! Application entry point and server initialization.
//! Uses `anyhow` for startup errors, but application-level
//! errors should use `kernel::error::AppError`.

use auth::PgAuthRepository;
use axum::{
    Router, http,
    http::{Method, header},
};
use base64::Engine;
use base64::engine::general_purpose;
use pow::{PowConfig, pow_router, store::PowStore};
use sqlx::postgres::PgPoolOptions;
use std::env;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tower_http::cors::{AllowHeaders, AllowMethods, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

// Re-export unified error types for use in handlers
pub use kernel::error::{
    app_error::{AppError, AppResult},
    kind::ErrorKind,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env file
    dotenvy::dotenv().ok();

    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                //.unwrap_or_else(|_| "api=debug,pow=debug,tower_http=debug".into()),
                .unwrap_or_else(|_| "api=info,auth=info,pow=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Database connection
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set in environment");

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await?;

    tracing::info!("Connected to database");

    // Run migrations
    sqlx::migrate!("../../../database/migrations")
        .run(&pool)
        .await?;

    tracing::info!("Migrations completed");

    // Startup cleanup: remove expired PoW data
    // Errors here should not prevent server startup
    let pow_store_for_cleanup = PowStore::new(pool.clone());
    match pow_store_for_cleanup.cleanup_expired().await {
        Ok((challenges, sessions, rate_limits)) => {
            tracing::info!(
                challenges_deleted = challenges,
                sessions_deleted = sessions,
                rate_limits_deleted = rate_limits,
                "POW session cleanup completed"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "POW session cleanup failed, continuing anyway"
            );
        }
    }

    let auth_store_for_cleanup = PgAuthRepository::new(pool.clone());
    match auth_store_for_cleanup.cleanup_expired().await {
        Ok(sessions) => {
            tracing::info!(
                sessions_deleted = sessions,
                "Auth session cleanup completed"
            );
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "Auth session cleanup failed, continuing anyway"
            );
        }
    }

    // PoW configuration
    let pow_config = if cfg!(debug_assertions) {
        PowConfig::development()
    } else {
        // In production, load secret from environment
        let secret_b64 =
            env::var("POW_SESSION_SECRET").expect("POW_SESSION_SECRET must be set in production");
        let secret_bytes = Engine::decode(&general_purpose::STANDARD, &secret_b64)?;
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&secret_bytes);
        PowConfig {
            session_secret: secret,
            ..PowConfig::default()
        }
    };

    let pow_store = PowStore::new(pool.clone());

    // CORS configuration
    let frontend_origins = env::var("FRONTEND_ORIGINS")
        .unwrap_or_else(|_| "http://localhost:40922,http://127.0.0.1:40922".to_string());

    let allowed_origins: Vec<http::HeaderValue> = frontend_origins
        .split(',')
        .filter_map(|origin| origin.trim().parse().ok())
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(allowed_origins)
        .allow_methods(AllowMethods::list([
            Method::GET,
            Method::POST,
            Method::OPTIONS,
        ]))
        .allow_headers(AllowHeaders::list([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
        ]))
        .allow_credentials(true);

    // Build router
    let app = Router::new()
        .nest("/api/pow", pow_router(pow_store, pow_config))
        .layer(TraceLayer::new_for_http())
        .layer(cors);

    // Start server
    let addr = SocketAddr::from(([0, 0, 0, 0], 31113));
    tracing::info!("Listening on {}", addr);

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
