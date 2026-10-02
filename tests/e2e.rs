//! End-to-end integration tests.
//!
//! Two `#[test]` cases, run serially (the docker entrypoint passes
//! `--test-threads=1`):
//!
//! 1. `taker_init_and_http_layer_against_regtest` — cheap (~13 s). Just
//!    proves `Taker::init` works against a real regtest bitcoind and that
//!    marketd's HTTP layer serves an empty store correctly. This is the
//!    test that would have caught the recent `messages → common_messages`
//!    rename and the `Taker::init(config)` signature change.
//!
//! 2. `maker_offer_flows_through_to_api_offers` — full stack (~2 min).
//!    Spawns a funded, fidelity-bonded `MakerServer` in-process, lets it
//!    broadcast its offer to the nostr relay, runs marketd's `sync_loop`
//!    against the same relay, and asserts the offer reaches
//!    `GET /api/makers` with the right fields.
//!
//! Both tests require `BITCOIND_EXE` and assume a nostr-rs-relay listening
//! on `ws://127.0.0.1:8000` (the docker entrypoint provides this).

#![cfg(feature = "integration-test")]

mod common;

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use bitcoind::bitcoincore_rpc::{
    Auth,
    bitcoin::{Amount, Network},
};
use marketd::{state::new_store, sync::sync_loop};
use openswap::{
    maker::{MakerBehavior, MakerServer, MakerServerConfig, start_server},
    protocol::ProtocolVersion,
    taker::{Taker, TakerInitConfig, api::ConnectionType},
    wallet::{AddressType, BackendConfig, CoreRpcConfig},
};
use serde_json::Value;

const NOSTR_RELAY: &str = "ws://127.0.0.1:8000";

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info,openswap=info")
        .try_init();
}

#[test]
fn taker_init_and_http_layer_against_regtest() {
    init_tracing();

    let tmp = tempfile::tempdir().expect("tempdir");
    let (_bitcoind, rpc_url, zmq_addr, creds) = common::init_bitcoind(tmp.path());

    let init_config = TakerInitConfig {
        data_dir: Some(tmp.path().join("taker")),
        wallet_name: "marketd-init-test-wallet".into(),
        backend: BackendConfig::CoreRpc(CoreRpcConfig {
            url: rpc_url,
            auth: Auth::UserPass(creds.user.clone(), creds.pass.clone()),
            wallet_name: "marketd-init-test-wallet".into(),
            zmq_addr,
        }),
        control_port: None,
        tor_auth_password: None,
        socks_port: 0,
        check_blocklist: None,
        password: Some("integration-test".into()),
        connection_type: ConnectionType::Clearnet,
        nostr_relays: vec![],
    };

    let taker = Taker::init(init_config).expect("Taker::init against regtest");
    let book = taker.fetch_offers().expect("fetch_offers");
    assert_eq!(book.all_makers().len(), 0, "no makers spawned in this test");

    let store = new_store();
    let guard = common::MarketdServerGuard::start(store);

    let resp = guard
        .agent
        .get(&guard.url("/api/health"))
        .call()
        .expect("GET /api/health");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.into_json().expect("decode /api/health");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["maker_count"], 0);
    assert_eq!(body["with_offer"], 0);

    let resp = guard
        .agent
        .get(&guard.url("/api/makers"))
        .call()
        .expect("GET /api/makers");
    assert_eq!(resp.status(), 200);
    let offers: Value = resp.into_json().expect("decode /api/makers");
    assert_eq!(offers.as_array().expect("array").len(), 0);
}

#[test]
fn maker_offer_flows_through_to_api_offers() {
    init_tracing();

    let tmp = tempfile::tempdir().expect("tempdir");
    let (bitcoind, rpc_url, zmq_addr, creds) = common::init_bitcoind(tmp.path());
    let bitcoind = Arc::new(bitcoind);

    let rpc_config = CoreRpcConfig {
        url: rpc_url.clone(),
        auth: Auth::UserPass(creds.user.clone(), creds.pass.clone()),
        // wallet_name is overwritten per-component by their init paths.
        wallet_name: "placeholder".into(),
        zmq_addr: zmq_addr.clone(),
    };

    // ───────── Maker ─────────
    let maker_net_port = common::free_port();
    let maker_rpc_port = common::free_port();
    let maker_wallet = format!("maker-{maker_net_port}");

    let maker_config = MakerServerConfig {
        data_dir: tmp.path().join(&maker_wallet),
        network_port: maker_net_port,
        rpc_port: maker_rpc_port,
        base_fee: 1000,
        amount_relative_fee_pct: 0.025,
        time_relative_fee_pct: 0.001,
        required_confirms: 1,
        check_blocklist: false,
        supported_protocols: vec![ProtocolVersion::Legacy, ProtocolVersion::Taproot],
        fidelity_amount: 5_000_000,
        fidelity_timelock: 950,
        fidelity_feerate: MakerServerConfig::default().fidelity_feerate,
        network: Network::Regtest,
        wallet_name: maker_wallet.clone(),
        backend: BackendConfig::CoreRpc(CoreRpcConfig {
            wallet_name: maker_wallet.clone(),
            ..rpc_config.clone()
        }),
        control_port: 0,
        socks_port: 0,
        tor_auth_password: String::new(),
        password: Some("integration-test".into()),
        nostr_relays: vec![NOSTR_RELAY.into()],
        name: "marketd-test-maker".into(),
    };

    let mut maker = MakerServer::init(maker_config).expect("MakerServer::init");
    maker.behavior = MakerBehavior::Normal;
    let maker = Arc::new(maker);

    // Fund the maker with 3 P2TR UTXOs of 0.05 BTC each → enough for the
    // 5M-sat fidelity bond + swap liquidity headroom.
    {
        let mut wallet = maker.wallet.write().expect("maker wallet write lock");
        for _ in 0..3 {
            let addr = wallet
                .get_next_external_address(AddressType::P2TR)
                .expect("get_next_external_address");
            common::send_to_address(&bitcoind, &addr, Amount::from_btc(0.05).unwrap());
        }
    }
    common::generate_blocks(&bitcoind, 1);
    maker
        .wallet
        .write()
        .expect("maker wallet write lock")
        .sync_and_save(&AtomicBool::new(false))
        .expect("sync_and_save after funding");

    // Background block generation. Confirms the fidelity bond tx and keeps
    // the chain advancing so the bond becomes spendable / observable.
    let block_gen_shutdown = Arc::new(AtomicBool::new(false));
    let block_gen_shutdown2 = block_gen_shutdown.clone();
    let bitcoind_for_blocks = bitcoind.clone();
    let block_gen_handle = thread::Builder::new()
        .name("e2e-block-gen".into())
        .spawn(move || {
            while !block_gen_shutdown2.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(3));
                common::generate_blocks(&bitcoind_for_blocks, 10);
            }
        })
        .expect("spawn block-gen thread");

    // Spawn the maker server. `start_server` blocks on the accept loop, so
    // it's expected to run for the full duration of the test.
    let maker_for_server = maker.clone();
    let maker_thread = thread::Builder::new()
        .name(format!("e2e-maker-{maker_net_port}"))
        .spawn(move || {
            if let Err(e) = start_server(maker_for_server) {
                eprintln!("[e2e] maker start_server returned: {e:?}");
            }
        })
        .expect("spawn maker thread");

    // Wait for fidelity bond setup + nostr broadcast to come up.
    let setup_deadline = Instant::now() + Duration::from_secs(180);
    while !maker.is_setup_complete.load(Ordering::Relaxed) {
        assert!(
            Instant::now() < setup_deadline,
            "maker did not complete setup within 180s"
        );
        thread::sleep(Duration::from_secs(2));
    }
    tracing::info!("maker is set up — port {maker_net_port}");

    // ───────── marketd sync_loop ─────────
    let store = new_store();
    let taker_config = TakerInitConfig {
        data_dir: Some(tmp.path().join("marketd-taker")),
        wallet_name: "marketd-taker-wallet".into(),
        backend: BackendConfig::CoreRpc(CoreRpcConfig {
            wallet_name: "marketd-taker-wallet".into(),
            ..rpc_config.clone()
        }),
        control_port: None,
        tor_auth_password: None,
        socks_port: 0,
        check_blocklist: None,
        password: Some("integration-test".into()),
        connection_type: ConnectionType::Clearnet,
        nostr_relays: vec![NOSTR_RELAY.into()],
    };

    let sync_store = store.clone();
    let _sync_thread = thread::Builder::new()
        .name("e2e-marketd-sync".into())
        .spawn(move || sync_loop(taker_config, 5, sync_store))
        .expect("spawn sync thread");

    // ───────── HTTP layer ─────────
    let guard = common::MarketdServerGuard::start(store.clone());

    // Poll /api/makers until a maker with an offer appears.
    let offer_deadline = Instant::now() + Duration::from_secs(120);
    let maker_json = loop {
        assert!(
            Instant::now() < offer_deadline,
            "marketd /api/makers never saw a maker with an offer (120s)"
        );

        let resp = guard
            .agent
            .get(&guard.url("/api/makers"))
            .call()
            .expect("GET /api/makers");
        let body: Value = resp.into_json().expect("decode /api/makers");
        let arr = body.as_array().expect("makers JSON is array");
        if let Some(m) = arr.iter().find(|m| !m["offer"].is_null()) {
            break m.clone();
        }
        thread::sleep(Duration::from_secs(2));
    };

    tracing::info!(?maker_json, "marketd saw a maker with an offer");

    assert_eq!(maker_json["address"], format!("127.0.0.1:{maker_net_port}"));
    assert_eq!(maker_json["state"]["kind"], "good");
    let offer = &maker_json["offer"];
    assert_eq!(offer["name"], "marketd-test-maker");
    assert_eq!(offer["base_fee"], 1000);
    assert!(offer["min_size"].as_u64().is_some_and(|min| min > 0));
    assert_eq!(offer["required_confirms"], 1);
    assert!(
        offer["fidelity_bond"]["amount"].as_u64().unwrap() >= 5_000_000,
        "fidelity bond amount should be at least the configured 5_000_000 sats"
    );
    assert!(
        offer["fidelity_bond"]["outpoint"]["txid"]
            .as_str()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        "fidelity bond outpoint.txid must be present and non-empty"
    );

    // ───────── Health endpoint reflects the offer count ─────────
    let resp = guard
        .agent
        .get(&guard.url("/api/health"))
        .call()
        .expect("GET /api/health");
    let body: Value = resp.into_json().expect("decode /api/health");
    assert_eq!(body["status"], "ok");
    assert!(body["maker_count"].as_u64().unwrap() >= 1);
    assert!(body["with_offer"].as_u64().unwrap() >= 1);
    assert!(body["last_sync"].is_number());

    // ───────── Teardown ─────────
    maker.shutdown.store(true, Ordering::Relaxed);
    block_gen_shutdown.store(true, Ordering::Relaxed);
    let _ = maker_thread.join();
    let _ = block_gen_handle.join();
}
