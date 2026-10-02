use clap::Parser;
use marketd::{
    config::Config,
    server,
    state::new_store,
    sync::{build_mainnet_taker_config, build_taker_config, sync_loop_for},
};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::parse();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_ansi(!cfg.no_color)
                .with_thread_names(true)
                .with_target(false),
        )
        .with(tracing_subscriber::EnvFilter::new(&cfg.log_filter))
        .init();

    tracing::info!(listen = %cfg.listen_addr, "Starting marketd");

    let signet_store = new_store();
    let mainnet_store = new_store();
    let signet_sync_store = signet_store.clone();
    let mainnet_sync_store = mainnet_store.clone();
    let signet_config = build_taker_config(&cfg);
    let mainnet_config = build_mainnet_taker_config(&cfg);
    let sync_interval = cfg.sync_interval_secs;

    std::thread::Builder::new()
        .name("marketd-sync-signet".into())
        .spawn(move || sync_loop_for("signet", signet_config, sync_interval, signet_sync_store))?;

    std::thread::Builder::new()
        .name("marketd-sync-mainnet".into())
        .spawn(move || {
            sync_loop_for("mainnet", mainnet_config, sync_interval, mainnet_sync_store)
        })?;

    tracing::info!(static_dir = %cfg.static_dir, "Serving frontend from");
    let app = server::router_with_mainnet(signet_store, mainnet_store, cfg.static_dir.clone());
    let listener = TcpListener::bind(&cfg.listen_addr).await?;
    tracing::info!(addr = %cfg.listen_addr, "HTTP server listening");
    axum::serve(listener, app).await?;

    Ok(())
}
