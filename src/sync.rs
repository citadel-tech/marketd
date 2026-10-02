use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openswap::{
    taker::{TakerInitConfig, api::ConnectionType, offers::MakerOfferCandidate},
    wallet::{BackendConfig, CoreRpcConfig, ElectrumConfig},
};

use crate::{config::Config, state};

const OFFER_RETENTION_SECS: u64 = 3 * 24 * 60 * 60;

/// Remove expired offers from the persisted book and the published snapshot.
/// A missing timestamp has no known age, so leave it for normal discovery.
fn prune_stale_offers<E: std::fmt::Debug>(
    makers: &mut Vec<MakerOfferCandidate>,
    now: u64,
    mut remove: impl FnMut(String) -> Result<bool, E>,
) {
    makers.retain(|maker| {
        let stale = maker
            .last_offer_update_ts
            .and_then(|updated| now.checked_sub(updated))
            .is_some_and(|age| age >= OFFER_RETENTION_SECS);
        if !stale {
            return true;
        }
        let address = maker.address.to_string();
        match remove(address.clone()) {
            Ok(_) => {
                tracing::info!(%address, "Pruned offer not updated for three days");
                false
            }
            Err(error) => {
                tracing::warn!(%address, ?error, "Failed to prune stale offer");
                true
            }
        }
    });
}

// Poll until a TCP port accepts a connection on the *first* resolved address.
// Matches the behaviour of `bitcoind::bitcoincore_rpc`'s simple_http client, which
// uses only addr.next() — so `localhost` resolving to ::1 first will silently
// pass a multi-addr probe but fail the actual RPC call.
fn wait_for_tcp(addr: &str, label: &str) {
    use std::net::{TcpStream, ToSocketAddrs};
    loop {
        let first = addr.to_socket_addrs().ok().and_then(|mut it| it.next());
        match first.and_then(|a| TcpStream::connect_timeout(&a, Duration::from_secs(5)).ok()) {
            Some(_) => {
                tracing::info!("{label} is reachable ({addr})");
                return;
            }
            None => {
                tracing::info!("Waiting for {label} ({addr})...");
                std::thread::sleep(Duration::from_secs(5));
            }
        }
    }
}

/// Translate the CLI `Config` into a `TakerInitConfig`. Kept separate so that
/// integration tests can build their own `TakerInitConfig` (e.g. Clearnet +
/// an in-process nostr relay) without constructing a fake CLI `Config`.
pub fn build_taker_config(cfg: &Config) -> TakerInitConfig {
    use bitcoind::bitcoincore_rpc::Auth;

    TakerInitConfig {
        data_dir: cfg.data_dir.clone(),
        backend: BackendConfig::CoreRpc(CoreRpcConfig {
            url: cfg.bitcoin_rpc_url.clone(),
            auth: Auth::UserPass(cfg.bitcoin_rpc_user.clone(), cfg.bitcoin_rpc_pass.clone()),
            wallet_name: cfg.wallet_name.clone(),
            zmq_addr: cfg.zmq_addr.clone(),
        }),
        wallet_name: cfg.wallet_name.clone(),
        control_port: Some(cfg.tor_control_port),
        tor_auth_password: Some(cfg.tor_auth_password.clone()),
        socks_port: cfg.tor_socks_port,
        password: Some(cfg.wallet_password.clone()),
        ..TakerInitConfig::default()
    }
}

/// Build the independent Mainnet scanner. It has a separate wallet and data
/// directory so its wallet, offerbook, and discovery cursors cannot mix with
/// the Bitcoin Core-backed scanner.
pub fn build_mainnet_taker_config(cfg: &Config) -> TakerInitConfig {
    TakerInitConfig {
        data_dir: Some(cfg.mainnet_data_dir.clone()),
        backend: BackendConfig::Electrum(ElectrumConfig {
            url: cfg.electrum_url.trim().to_owned(),
            socks5: cfg
                .electrum_tor
                .then(|| format!("127.0.0.1:{}", cfg.tor_socks_port)),
            ..ElectrumConfig::default()
        }),
        wallet_name: cfg.mainnet_wallet_name.clone(),
        control_port: Some(cfg.tor_control_port),
        tor_auth_password: Some(cfg.tor_auth_password.clone()),
        socks_port: cfg.tor_socks_port,
        password: Some(cfg.wallet_password.clone()),
        ..TakerInitConfig::default()
    }
}

pub fn sync_loop(init_config: TakerInitConfig, sync_interval_secs: u64, store: state::SharedStore) {
    sync_loop_for("default", init_config, sync_interval_secs, store);
}

pub fn sync_loop_for(
    scanner: &'static str,
    init_config: TakerInitConfig,
    sync_interval_secs: u64,
    store: state::SharedStore,
) {
    use openswap::taker::Taker;

    match &init_config.backend {
        BackendConfig::CoreRpc(rpc) => {
            tracing::info!(scanner, url = %rpc.url, "Using Bitcoin Core backend");
            wait_for_tcp(&rpc.url, "Bitcoin RPC");
        }
        BackendConfig::Electrum(electrum) => {
            tracing::info!(
                scanner,
                url = %electrum.url,
                tor = electrum.socks5.is_some(),
                "Using Electrum backend"
            );
        }
    }
    if init_config.connection_type == ConnectionType::Tor
        && let Some(port) = init_config.control_port
    {
        wait_for_tcp(&format!("127.0.0.1:{port}"), "Tor control port");
    }

    let taker = loop {
        tracing::info!(scanner, "Initializing Taker...");
        match Taker::init(init_config.clone()) {
            Ok(t) => {
                tracing::info!(scanner, "Taker initialized successfully");
                break t;
            }
            Err(e) => {
                tracing::warn!(scanner, error = ?e, "Taker init failed, retrying in 15s (waiting for blockchain backend / Tor)");
                std::thread::sleep(Duration::from_secs(15));
            }
        }
    };

    loop {
        if let Err(e) = taker.sync_offerbook_and_wait() {
            tracing::error!(scanner, error = ?e, "sync_offerbook_and_wait failed");
            std::thread::sleep(Duration::from_secs(sync_interval_secs));
            continue;
        }

        let book = match taker.fetch_offers() {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(scanner, error = ?e, "fetch_offers failed");
                std::thread::sleep(Duration::from_secs(sync_interval_secs));
                continue;
            }
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut candidates = book.all_makers();
        prune_stale_offers(&mut candidates, timestamp, |address| {
            taker.remove_maker(address)
        });

        let makers: Vec<state::ApiMaker> = candidates
            .iter()
            .map(|m| state::ApiMaker::from_candidate(m, timestamp))
            .collect();

        let count = makers.len();
        let with_offer = makers.iter().filter(|m| m.offer.is_some()).count();
        {
            let mut s = store.write().unwrap();
            s.makers = makers;
            s.last_sync = Some(timestamp);
        }

        tracing::info!(
            scanner,
            count,
            with_offer,
            "Sync done, sleeping {sync_interval_secs}s"
        );
        std::thread::sleep(Duration::from_secs(sync_interval_secs));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use openswap::taker::offers::{
        BanReason, BanRecord, MakerState, UnavailableReason, UnavailableState,
    };
    use serde_json::json;

    fn maker(name: &str, updated: Option<u64>, state: MakerState) -> MakerOfferCandidate {
        #[cfg(not(feature = "integration-test"))]
        let address = format!("{name}.onion");
        #[cfg(feature = "integration-test")]
        let address = format!("{name}.onion:6102");

        // Deserialize the same persisted shape OpenSwap reads. The candidate
        // contains private migration fields, so external users cannot build it
        // with a struct literal.
        serde_json::from_value(json!({
            "address": address,
            "fidelity_outpoint": null,
            "offer": null,
            "state": state,
            "protocol": null,
            "last_offer_update_ts": updated,
            "next_offer_check_ts": null
        }))
        .unwrap()
    }

    fn unavailable(attempts: u32) -> MakerState {
        MakerState::Unavailable(UnavailableState {
            reason: UnavailableReason::LegacyStatus,
            since_ts: None,
            last_attempt_ts: None,
            attempts,
        })
    }

    fn banned() -> MakerState {
        MakerState::Banned(BanRecord {
            reason: BanReason::LegacyProvenViolation,
            recorded_at_ts: 1,
        })
    }

    #[test]
    fn electrum_config_matches_taker_backend_selection() {
        let cfg = Config::try_parse_from([
            "marketd",
            "--electrum",
            "ssl://electrum.example.org:50002",
            "--electrum-tor",
            "--tor-socks-port",
            "19050",
            "--mainnet-wallet-name",
            "custom-mainnet-wallet",
            "--mainnet-data-dir",
            "custom-mainnet-data",
        ])
        .unwrap();

        let taker = build_mainnet_taker_config(&cfg);
        assert_eq!(taker.wallet_name, "custom-mainnet-wallet");
        assert_eq!(
            taker.data_dir.as_deref(),
            Some(std::path::Path::new("custom-mainnet-data"))
        );
        assert_eq!(taker.socks_port, 19050);
        match taker.backend {
            BackendConfig::Electrum(electrum) => {
                assert_eq!(electrum.url, "ssl://electrum.example.org:50002");
                assert_eq!(electrum.socks5.as_deref(), Some("127.0.0.1:19050"));
            }
            BackendConfig::CoreRpc(_) => panic!("expected Electrum backend"),
        }
    }

    #[test]
    fn blockstream_electrum_is_the_default_backend() {
        let cfg = Config::try_parse_from(["marketd"]).unwrap();
        let taker = build_mainnet_taker_config(&cfg);

        match taker.backend {
            BackendConfig::Electrum(electrum) => {
                assert_eq!(electrum.url, "ssl://electrum.blockstream.info:50002");
                assert_eq!(electrum.socks5, None);
            }
            BackendConfig::CoreRpc(_) => panic!("expected Electrum backend"),
        }
    }

    #[test]
    fn bitcoin_core_config_remains_the_default_api_backend() {
        let cfg = Config::try_parse_from(["marketd"]).unwrap();
        let taker = build_taker_config(&cfg);

        match taker.backend {
            BackendConfig::CoreRpc(core) => {
                assert_eq!(core.url, "localhost:18443");
                assert_eq!(core.wallet_name, "marketd-wallet");
            }
            BackendConfig::Electrum(_) => panic!("expected Bitcoin Core backend"),
        }
    }

    #[test]
    fn prunes_three_day_old_records_regardless_of_state() {
        let now = OFFER_RETENTION_SECS + 100;
        let mut makers = vec![
            maker("good", Some(100), MakerState::Good),
            maker("banned", Some(99), banned()),
            maker("offline", Some(99), unavailable(3)),
            maker("fresh", Some(101), MakerState::Good),
            maker("future", Some(now + 1), MakerState::Good),
            maker("unknown", None, banned()),
        ];
        let mut removed = Vec::new();
        prune_stale_offers(&mut makers, now, |address| {
            removed.push(address);
            Ok::<_, ()>(true)
        });
        let expected: Vec<_> = ["good", "banned", "offline"]
            .iter()
            .map(|name| maker(name, None, MakerState::Good).address.to_string())
            .collect();
        assert_eq!(removed, expected);
        assert_eq!(makers.len(), 3);
        assert_eq!(
            makers[0].address,
            maker("fresh", None, MakerState::Good).address
        );
    }

    #[test]
    fn failed_removals_stay_in_snapshot_and_absent_records_leave_it() {
        let mut makers = vec![maker("old", Some(1), banned())];
        let now = OFFER_RETENTION_SECS + 1;
        prune_stale_offers(&mut makers, now, |_| Err::<bool, _>("disk error"));
        assert_eq!(makers.len(), 1);
        prune_stale_offers(&mut makers, now, |_| Ok::<_, ()>(false));
        assert!(makers.is_empty());
    }
}
