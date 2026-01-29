use crate::{config::ProxyConfig, session::SessionManager, user_manager::UserManager};
use axum::{
    Router,
    extract::{Json, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use common::config::UserConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tracing::info;

#[derive(Clone)]
struct AppState {
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    session_manager: Arc<SessionManager>,
}

pub async fn start_server(
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    session_manager: Arc<SessionManager>,
) -> anyhow::Result<()> {
    let state = AppState {
        config: config.clone(),
        user_manager,
        session_manager,
    };

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/config", get(get_config))
        .route("/config", put(update_config))
        .route("/users", get(list_users))
        .route("/users", post(add_user))
        .route("/users/:username", delete(remove_user))
        .route("/users/:username/bandwidth", put(update_bandwidth))
        .route("/users/:username/stats", get(get_user_stats))
        .route("/connections", get(list_connections))
        .route("/stats", get(get_stats))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&config.api_listen_addr).await?;
    info!("API server listening on {}", config.api_listen_addr);

    axum::serve(listener, app).await?;
    Ok(())
}

// Health check endpoint
async fn health_check() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))
}

// Get proxy configuration
async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    #[derive(Serialize)]
    struct ConfigResponse {
        listen_addr: String,
        api_listen_addr: String,
        max_connections_per_user: usize,
        session_timeout_secs: u64,
        rsa_public_key: String,
    }

    let response = ConfigResponse {
        listen_addr: state.config.listen_addr.clone(),
        api_listen_addr: state.config.api_listen_addr.clone(),
        max_connections_per_user: state.config.max_connections_per_user,
        session_timeout_secs: state.config.session_timeout_secs,
        rsa_public_key: state.config.rsa_public_key.clone(),
    };

    Json(response)
}

// Update configuration
#[derive(Deserialize)]
struct UpdateConfigRequest {
    max_connections_per_user: Option<usize>,
    session_timeout_secs: Option<u64>,
}

async fn update_config(
    State(state): State<AppState>,
    Json(req): Json<UpdateConfigRequest>,
) -> impl IntoResponse {
    let requested_max = req
        .max_connections_per_user
        .unwrap_or(state.config.max_connections_per_user);
    let requested_timeout = req
        .session_timeout_secs
        .unwrap_or(state.config.session_timeout_secs);

    info!(
        max_connections_per_user = requested_max,
        session_timeout_secs = requested_timeout,
        "Received config update request"
    );

    Json(serde_json::json!({
        "success": true,
        "message": "Configuration update queued (restart required for some changes)",
        "requested_settings": {
            "max_connections_per_user": requested_max,
            "session_timeout_secs": requested_timeout
        }
    }))
}

// List all users
async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    let users = state.user_manager.list_users();
    Json(users)
}

// Add a new user
#[derive(Deserialize)]
struct AddUserRequest {
    username: String,
    password: String,
    bandwidth_limit: Option<u64>,
    rsa_public_key: Option<String>,
    rsa_private_key: Option<String>,
}

async fn add_user(
    State(state): State<AppState>,
    Json(req): Json<AddUserRequest>,
) -> impl IntoResponse {
    let (public_key, private_key) =
        if let (Some(pub_key), Some(priv_key)) = (req.rsa_public_key, req.rsa_private_key) {
            (pub_key, priv_key)
        } else {
            match common::crypto::generate_rsa_keypair() {
                Ok((pub_key, priv_key)) => (pub_key, priv_key),
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({
                            "success": false,
                            "message": format!("Failed to generate RSA keys: {}", e)
                        })),
                    );
                }
            }
        };

    let user_config = UserConfig {
        username: req.username.clone(),
        password: req.password,
        rsa_public_key: public_key.clone(),
        rsa_private_key: private_key,
        bandwidth_limit: req.bandwidth_limit,
    };

    let success = state.user_manager.add_user(req.username, user_config);

    if success {
        (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "success": true,
                "message": "User added successfully",
                "rsa_public_key": public_key
            })),
        )
    } else {
        (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "success": false,
                "message": "User already exists"
            })),
        )
    }
}

// Remove a user
async fn remove_user(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    let success = state.user_manager.remove_user(&username);

    if success {
        Json(serde_json::json!({
            "success": true,
            "message": "User removed successfully"
        }))
    } else {
        Json(serde_json::json!({
            "success": false,
            "message": "User not found"
        }))
    }
}

// Update user bandwidth limit
#[derive(Deserialize)]
struct UpdateBandwidthRequest {
    bandwidth_limit: Option<u64>,
}

async fn update_bandwidth(
    State(state): State<AppState>,
    Path(username): Path<String>,
    Json(req): Json<UpdateBandwidthRequest>,
) -> impl IntoResponse {
    let success = state
        .user_manager
        .update_bandwidth_limit(&username, req.bandwidth_limit);

    if success {
        Json(serde_json::json!({
            "success": true,
            "message": "Bandwidth limit updated"
        }))
    } else {
        Json(serde_json::json!({
            "success": false,
            "message": "User not found"
        }))
    }
}

// Get user statistics
async fn get_user_stats(
    State(state): State<AppState>,
    Path(username): Path<String>,
) -> impl IntoResponse {
    if let Some(stats) = state.user_manager.get_user_stats(&username) {
        (StatusCode::OK, Json(serde_json::to_value(stats).unwrap()))
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "User not found"
            })),
        )
    }
}

// List active connections
async fn list_connections(State(state): State<AppState>) -> impl IntoResponse {
    let sessions = state.session_manager.list_sessions();

    let connections: Vec<_> = sessions
        .iter()
        .map(|session| {
            serde_json::json!({
                "session_id": session.session_id,
                "username": session.username,
                "created_at": session.created_at.elapsed().as_secs(),
                "last_activity": session.last_activity.elapsed().as_secs()
            })
        })
        .collect();

    Json(connections)
}

// Get overall statistics
async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let total_users = state.user_manager.list_users().len();
    let active_sessions = state.session_manager.session_count();

    let mut total_connections = 0;
    let mut total_bandwidth = 0u64;

    for username in state.user_manager.list_users() {
        if let Some(stats) = state.user_manager.get_user_stats(&username) {
            total_connections += stats.active_connections;
            total_bandwidth += stats.total_bytes;
        }
    }

    Json(serde_json::json!({
        "total_users": total_users,
        "active_sessions": active_sessions,
        "total_connections": total_connections,
        "total_bandwidth_bytes": total_bandwidth
    }))
}
