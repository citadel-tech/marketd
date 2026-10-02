use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Json,
    routing::get,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tower_http::{
    cors::CorsLayer,
    services::{ServeDir, ServeFile},
};

use crate::state::{ApiMaker, ApiMakerState, SharedStore, new_store};

#[derive(Clone)]
struct ApiStores {
    signet: SharedStore,
    mainnet: SharedStore,
}

pub fn router(store: SharedStore, static_dir: String) -> Router {
    router_with_mainnet(store, new_store(), static_dir)
}

pub fn router_with_mainnet(
    signet: SharedStore,
    mainnet: SharedStore,
    static_dir: String,
) -> Router {
    let index = format!("{static_dir}/index.html");
    let spa = ServeDir::new(&static_dir).not_found_service(ServeFile::new(index));

    Router::new()
        .route("/api/makers", get(get_signet_makers))
        .route("/api/health", get(get_signet_health))
        .route("/api/mainnet/makers", get(get_mainnet_makers))
        .route("/api/mainnet/health", get(get_mainnet_health))
        .with_state(ApiStores { signet, mainnet })
        .layer(CorsLayer::permissive())
        .fallback_service(spa)
}

#[derive(Serialize, Deserialize)]
struct MakerQueryParams {
    state: Option<ApiMakerState>,
}

async fn get_signet_makers(
    State(stores): State<ApiStores>,
    Query(params): Query<MakerQueryParams>,
) -> Result<Json<Value>, StatusCode> {
    get_makers(&stores.signet, params)
}

async fn get_mainnet_makers(
    State(stores): State<ApiStores>,
    Query(params): Query<MakerQueryParams>,
) -> Result<Json<Value>, StatusCode> {
    get_makers(&stores.mainnet, params)
}

fn get_makers(store: &SharedStore, params: MakerQueryParams) -> Result<Json<Value>, StatusCode> {
    let makers = store
        .read()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .makers
        .clone();
    let makers = makers
        .iter()
        .filter(|m| params.state.as_ref().is_none_or(|state| state == &m.state))
        .collect::<Vec<&ApiMaker>>();

    Ok(Json(json!(makers)))
}

async fn get_signet_health(State(stores): State<ApiStores>) -> Json<Value> {
    get_health(&stores.signet, "signet", "bitcoin_core")
}

async fn get_mainnet_health(State(stores): State<ApiStores>) -> Json<Value> {
    get_health(&stores.mainnet, "mainnet", "electrum")
}

fn get_health(store: &SharedStore, network: &str, backend: &str) -> Json<Value> {
    let s = store.read().unwrap();
    let with_offer = s.makers.iter().filter(|m| m.offer.is_some()).count();
    Json(json!({
        "status": "ok",
        "network": network,
        "backend": backend,
        "maker_count": s.makers.len(),
        "with_offer": with_offer,
        "last_sync": s.last_sync,
    }))
}
