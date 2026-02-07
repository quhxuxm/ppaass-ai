use crate::bandwidth::BandwidthMonitor;
use crate::config::ProxyConfig;
use crate::error::Result;
use crate::user_manager::UserManager;
use axum::{
    Router,
    extract::{Json, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post, put},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::trace::TraceLayer;
use tracing::{info, instrument};

pub struct ApiServer {
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
}

#[derive(Clone)]
struct AppState {
    config: Arc<ProxyConfig>,
    user_manager: Arc<UserManager>,
    bandwidth_monitor: Arc<BandwidthMonitor>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddUserRequest {
    username: String,
    bandwidth_limit_mbps: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AddUserResponse {
    success: bool,
    message: String,
    private_key: Option<String>,
    public_key: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RemoveUserRequest {
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct GenericResponse {
    success: bool,
    message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UsersListResponse {
    users: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct BandwidthStats {
    username: String,
    bytes_sent: u64,
    bytes_received: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct BandwidthStatsResponse {
    stats: Vec<BandwidthStats>,
}

#[derive(Debug, Serialize, Deserialize)]
struct HealthResponse {
    status: String,
    version: String,
}

impl ApiServer {
    pub fn new(
        config: Arc<ProxyConfig>,
        user_manager: Arc<UserManager>,
        bandwidth_monitor: Arc<BandwidthMonitor>,
    ) -> Self {
        Self {
            config,
            user_manager,
            bandwidth_monitor,
        }
    }

    #[instrument(skip(self))]
    pub async fn run(self) -> Result<()> {
        let app_state = AppState {
            config: self.config.clone(),
            user_manager: self.user_manager,
            bandwidth_monitor: self.bandwidth_monitor,
        };

        let app = Router::new()
            .route("/health", get(health_check))
            .route("/api/users", post(add_user))
            .route("/api/users", delete(remove_user))
            .route("/api/users", get(list_users))
            .route("/api/stats/bandwidth", get(get_bandwidth_stats))
            .route("/api/config", get(get_config))
            .route("/api/config", put(update_config))
            .layer(TraceLayer::new_for_http())
            .with_state(app_state);

        info!("Starting API server on {}", self.config.api_addr);

        let listener = tokio::net::TcpListener::bind(&self.config.api_addr).await?;
        axum::serve(listener, app).await?;

        Ok(())
    }
}

async fn health_check() -> impl IntoResponse {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

#[instrument(skip(state))]
async fn add_user(
    State(state): State<AppState>,
    Json(request): Json<AddUserRequest>,
) -> impl IntoResponse {
    info!("API: Add user request for {}", request.username);

    match state
        .user_manager
        .as_ref()
        .add_user(request.username.clone(), request.bandwidth_limit_mbps)
        .await
    {
        Ok((private_key, public_key)) => {
            // Register user in bandwidth monitor
            state
                .bandwidth_monitor
                .register_user(request.username.clone(), request.bandwidth_limit_mbps);

            (
                StatusCode::OK,
                Json(AddUserResponse {
                    success: true,
                    message: format!("User {} added successfully", request.username),
                    private_key: Some(private_key),
                    public_key: Some(public_key),
                }),
            )
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(AddUserResponse {
                success: false,
                message: format!("Failed to add user: {}", e),
                private_key: None,
                public_key: None,
            }),
        ),
    }
}

#[instrument(skip(state))]
async fn remove_user(
    State(state): State<AppState>,
    Json(request): Json<RemoveUserRequest>,
) -> impl IntoResponse {
    info!("API: Remove user request for {}", request.username);

    match state
        .user_manager
        .as_ref()
        .remove_user(&request.username)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(GenericResponse {
                success: true,
                message: format!("User {} removed successfully", request.username),
            }),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(GenericResponse {
                success: false,
                message: format!("Failed to remove user: {}", e),
            }),
        ),
    }
}

#[instrument(skip(state))]
async fn list_users(State(state): State<AppState>) -> impl IntoResponse {
    match state.user_manager.as_ref().list_users().await {
        Ok(users) => (StatusCode::OK, Json(UsersListResponse { users })),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(UsersListResponse { users: vec![] }),
        ),
    }
}

#[instrument(skip(state))]
async fn get_bandwidth_stats(State(state): State<AppState>) -> impl IntoResponse {
    let stats = state
        .bandwidth_monitor
        .get_all_stats()
        .into_iter()
        .map(|(username, bytes_sent, bytes_received)| BandwidthStats {
            username,
            bytes_sent,
            bytes_received,
        })
        .collect();

    Json(BandwidthStatsResponse { stats })
}

async fn get_config(State(state): State<AppState>) -> impl IntoResponse {
    Json(state.config.as_ref().clone())
}

#[instrument(skip(_state, _new_config))]
async fn update_config(
    State(_state): State<AppState>,
    Json(_new_config): Json<ProxyConfig>,
) -> impl IntoResponse {
    // In a real implementation, you would update the configuration
    // and potentially reload parts of the system
    info!("API: Update config request");

    (
        StatusCode::OK,
        Json(GenericResponse {
            success: true,
            message: "Configuration updated (not implemented)".to_string(),
        }),
    )
}
