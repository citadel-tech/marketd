use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Clone, Debug)]
#[command(name = "marketd", about = "OpenSwap market offer aggregator daemon")]
pub struct Config {
    /// OpenSwap data directory for the Bitcoin Core-backed Signet scanner.
    #[arg(long, env = "MARKETD_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    #[arg(long, env = "MARKETD_WALLET_NAME", default_value = "marketd-wallet")]
    pub wallet_name: String,

    #[arg(long, env = "MARKETD_MAINNET_DATA_DIR", default_value = "data/mainnet")]
    pub mainnet_data_dir: PathBuf,

    #[arg(
        long,
        env = "MARKETD_MAINNET_WALLET_NAME",
        default_value = "marketd-mainnet"
    )]
    pub mainnet_wallet_name: String,

    #[arg(
        long,
        env = "MARKETD_BITCOIN_RPC_URL",
        default_value = "localhost:18443"
    )]
    pub bitcoin_rpc_url: String,

    #[arg(long, env = "MARKETD_BITCOIN_RPC_USER", default_value = "user")]
    pub bitcoin_rpc_user: String,

    #[arg(long, env = "MARKETD_BITCOIN_RPC_PASS", default_value = "password")]
    pub bitcoin_rpc_pass: String,

    #[arg(
        long,
        env = "MARKETD_ZMQ_ADDR",
        default_value = "tcp://127.0.0.1:28332"
    )]
    pub zmq_addr: String,

    /// Electrum server URL (for example `ssl://electrum.example.org:50002`).
    /// Used by the separate Mainnet scanner. The server's genesis header is
    /// checked by OpenSwap before discovery starts.
    #[arg(
        long = "electrum",
        env = "MARKETD_ELECTRUM_URL",
        default_value = "ssl://electrum.blockstream.info:50002"
    )]
    pub electrum_url: String,

    /// Route Electrum traffic through Marketd's Tor SOCKS proxy.
    #[arg(long, env = "MARKETD_ELECTRUM_TOR", requires = "electrum_url")]
    pub electrum_tor: bool,

    #[arg(long, env = "MARKETD_WALLET_PASSWORD", default_value = "openswap")]
    pub wallet_password: String,

    #[arg(long, env = "MARKETD_TOR_CONTROL_PORT", default_value_t = 9051)]
    pub tor_control_port: u16,

    #[arg(long, env = "MARKETD_TOR_SOCKS_PORT", default_value_t = 9050)]
    pub tor_socks_port: u16,

    #[arg(long, env = "MARKETD_TOR_AUTH_PASSWORD", default_value = "")]
    pub tor_auth_password: String,

    #[arg(long, env = "MARKETD_SYNC_INTERVAL_SECS", default_value_t = 60)]
    pub sync_interval_secs: u64,

    #[arg(long, env = "MARKETD_LISTEN_ADDR", default_value = "127.0.0.1:3000")]
    pub listen_addr: String,

    #[arg(long, env = "MARKETD_STATIC_DIR", default_value = "web/dist")]
    pub static_dir: String,

    /// Log filter directive (e.g. "debug", "tower_http=debug,info")
    #[arg(
        long,
        default_value = "tower_http=debug,info",
        env = "MARKETD_LOG_FILTER"
    )]
    pub log_filter: String,

    /// Disable ANSI colors in log output (useful for log files / CI)
    #[arg(long, default_value_t = false, env = "MARKETD_NO_COLOR")]
    pub no_color: bool,
}
