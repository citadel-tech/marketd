//! Shared helpers for integration tests.
//!
//! - Regtest bitcoind boot helper (`init_bitcoind`), ported from
//!   `maker-dashboard/tests/integration_test.rs` so the two crates stay in
//!   sync. `init_bitcoind` and the mining/sending helpers require
//!   `BITCOIND_EXE` to be set; the rest do not.
//! - `MarketdServerGuard`: spawns marketd's HTTP router on a free port in a
//!   background thread, with graceful shutdown on drop.

#![allow(dead_code)]

use std::{
    fs,
    net::TcpListener,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitcoind::{
    BitcoinD,
    bitcoincore_rpc::{
        RpcApi,
        bitcoin::{Address, Amount, Network, Txid},
    },
};

/// Bind to `127.0.0.1:0`, read the port the kernel assigned, then drop the
/// listener. Racy by definition but it is the same approach maker-dashboard
/// uses and it has been good enough in practice.
pub fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind for free port")
        .local_addr()
        .unwrap()
        .port()
}

/// Cookie-based credentials for the regtest bitcoind we spawn.
#[derive(Clone)]
pub struct RpcCreds {
    pub user: String,
    pub pass: String,
}

impl RpcCreds {
    pub fn from_cookie(cookie_file: &Path) -> Self {
        let raw = fs::read_to_string(cookie_file)
            .unwrap_or_else(|e| panic!("Cannot read cookie {}: {e}", cookie_file.display()));
        let (user, pass) = raw
            .trim()
            .split_once(':')
            .unwrap_or_else(|| panic!("Unexpected cookie format: {raw:?}"));
        Self {
            user: user.to_owned(),
            pass: pass.to_owned(),
        }
    }
}

/// Mine `n` blocks to a fresh address on the regtest node.
pub fn generate_blocks(bitcoind: &BitcoinD, n: u64) {
    let addr = match bitcoind.client.get_new_address(None, None) {
        Ok(a) => a.require_network(Network::Regtest).unwrap(),
        Err(_) => return,
    };
    let _ = bitcoind.client.generate_to_address(n, &addr);
}

/// Send `amount` to `addr` on the regtest node and return the txid.
pub fn send_to_address(bitcoind: &BitcoinD, addr: &Address, amount: Amount) -> Txid {
    bitcoind
        .client
        .send_to_address(addr, amount, None, None, None, None, None, None)
        .unwrap()
}

/// Start a regtest `bitcoind` with the flags OpenSwap needs.
///
/// Returns the running node (drop it to stop), the `host:port` RPC URL with
/// the `http://` prefix stripped (the form `TakerInitConfig.rpc_config.url`
/// expects), the ZMQ address, and cookie-derived RPC credentials.
pub fn init_bitcoind(base_dir: &Path) -> (BitcoinD, String, String, RpcCreds) {
    let zmq_addr = format!("tcp://127.0.0.1:{}", free_port());
    let zmq_rawtx = format!("-zmqpubrawtx={zmq_addr}");
    let zmq_block = format!("-zmqpubrawblock={zmq_addr}");

    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1");
    conf.args.push("-rest=1");
    // `Conf::args` is `Vec<&'static str>`; the only way to push a runtime
    // string is to leak it. Bounded per test run.
    conf.args.push(Box::leak(zmq_rawtx.into_boxed_str()));
    conf.args.push(Box::leak(zmq_block.into_boxed_str()));
    conf.staticdir = Some(base_dir.join(".bitcoin"));

    let exe_path = bitcoind::exe_path().expect(
        "bitcoind binary not found — set BITCOIND_EXE or run via `make test-integration-docker`",
    );
    let bd = BitcoinD::with_conf(exe_path, &conf).expect("start bitcoind");
    generate_blocks(&bd, 101);

    let creds = RpcCreds::from_cookie(&bd.params.cookie_file);
    let rpc_url = bd.rpc_url().trim_start_matches("http://").to_string();
    (bd, rpc_url, zmq_addr, creds)
}

/// Starts marketd's HTTP router on a free port in a background tokio runtime,
/// with graceful shutdown when dropped.
///
/// The frontend `static_dir` is irrelevant for the API endpoints we test,
/// so any existing directory works — defaults to the system temp dir.
pub struct MarketdServerGuard {
    pub base_url: String,
    pub agent: ureq::Agent,
    shutdown: Arc<AtomicBool>,
    _thread: thread::JoinHandle<()>,
}

impl MarketdServerGuard {
    pub fn start(store: marketd::state::SharedStore) -> Self {
        Self::start_dual(store, marketd::state::new_store())
    }

    pub fn start_dual(
        signet_store: marketd::state::SharedStore,
        mainnet_store: marketd::state::SharedStore,
    ) -> Self {
        let port = free_port();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown2 = shutdown.clone();
        let static_dir = std::env::temp_dir().to_string_lossy().to_string();

        let thread = thread::Builder::new()
            .name("marketd-test-http".into())
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                rt.block_on(async move {
                    let app = marketd::server::router_with_mainnet(
                        signet_store,
                        mainnet_store,
                        static_dir,
                    );
                    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
                        .await
                        .expect("bind test HTTP listener");
                    axum::serve(listener, app)
                        .with_graceful_shutdown(async move {
                            while !shutdown2.load(Ordering::Relaxed) {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                        })
                        .await
                        .expect("axum::serve");
                });
            })
            .expect("spawn marketd test HTTP thread");

        // Wait up to 5s for the server to accept connections.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if std::net::TcpStream::connect(format!("127.0.0.1:{port}")).is_ok() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "marketd test server did not bind within 5s"
            );
            thread::sleep(Duration::from_millis(50));
        }

        Self {
            base_url: format!("http://127.0.0.1:{port}"),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(5))
                .build(),
            shutdown,
            _thread: thread,
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base_url)
    }
}

impl Drop for MarketdServerGuard {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}
