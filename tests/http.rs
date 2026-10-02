//! HTTP layer smoke test.
//!
//! Boots only marketd's axum router against a hand-built `SharedStore` (no
//! bitcoind, no sync) and asserts the two API endpoints return the expected
//! JSON shape. Catches regressions in routing, JSON serialization, and the
//! state types — the layer most likely to silently break a frontend.

mod common;

use marketd::state::{
    ApiBanReason, ApiFidelityBond, ApiMaker, ApiMakerState, ApiOffer, ApiOutpoint,
    ApiUnavailableReason, new_store,
};
use serde_json::Value;

#[test]
fn health_and_makers_empty_store() {
    let store = new_store();
    let guard = common::MarketdServerGuard::start(store);

    let resp = guard
        .agent
        .get(&guard.url("/api/health"))
        .call()
        .expect("GET /api/health");
    assert_eq!(resp.status(), 200);
    let body: Value = resp.into_json().expect("health JSON");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["network"], "signet");
    assert_eq!(body["backend"], "bitcoin_core");
    assert_eq!(body["maker_count"], 0);
    assert_eq!(body["with_offer"], 0);
    assert!(body["last_sync"].is_null());

    let resp = guard
        .agent
        .get(&guard.url("/api/makers"))
        .call()
        .expect("GET /api/makers");
    assert_eq!(resp.status(), 200);
    let makers: Value = resp.into_json().expect("makers JSON");
    assert_eq!(makers.as_array().expect("array").len(), 0);
}

#[test]
fn mainnet_routes_use_the_independent_electrum_store() {
    let signet_store = new_store();
    let mainnet_store = new_store();
    mainnet_store.write().unwrap().makers.push(ApiMaker {
        address: "mainnet-maker.onion".into(),
        state: ApiMakerState::Good,
        protocol: Some("taproot"),
        timestamp: 1_700_000_001,
        last_offer_update_ts: None,
        next_offer_check_ts: None,
        offer: None,
    });

    let guard = common::MarketdServerGuard::start_dual(signet_store, mainnet_store);

    let signet: Value = guard
        .agent
        .get(&guard.url("/api/makers"))
        .call()
        .expect("GET /api/makers")
        .into_json()
        .expect("signet makers JSON");
    assert_eq!(signet.as_array().unwrap().len(), 0);

    let mainnet: Value = guard
        .agent
        .get(&guard.url("/api/mainnet/makers"))
        .call()
        .expect("GET /api/mainnet/makers")
        .into_json()
        .expect("mainnet makers JSON");
    assert_eq!(mainnet.as_array().unwrap().len(), 1);
    assert_eq!(mainnet[0]["address"], "mainnet-maker.onion");

    let health: Value = guard
        .agent
        .get(&guard.url("/api/mainnet/health"))
        .call()
        .expect("GET /api/mainnet/health")
        .into_json()
        .expect("mainnet health JSON");
    assert_eq!(health["network"], "mainnet");
    assert_eq!(health["backend"], "electrum");
    assert_eq!(health["maker_count"], 1);
}

#[test]
fn makers_returns_seeded_data() {
    let store = new_store();
    {
        let mut s = store.write().unwrap();
        // A "Good" maker with a populated offer.
        s.makers.push(ApiMaker {
            address: "127.0.0.1:6102".into(),
            state: ApiMakerState::Good,
            protocol: Some("taproot"),
            timestamp: 1_234_567_890,
            last_offer_update_ts: Some(1_234_567_890),
            next_offer_check_ts: Some(1_234_567_950),
            offer: Some(ApiOffer {
                name: Some("Alice's Maker".into()),
                base_fee: 1000,
                amount_relative_fee_pct: 0.5,
                time_relative_fee_pct: 0.1,
                min_size: 10_000,
                max_size: 100_000_000,
                required_confirms: 1,
                minimum_locktime: 144,
                tweakable_point: "02abcd".into(),
                fidelity_bond: ApiFidelityBond {
                    amount: 5_000_000,
                    outpoint: ApiOutpoint {
                        txid: "deadbeef".into(),
                        vout: 0,
                    },
                    lock_time: 800_000,
                    cert_hash: "feedface".into(),
                    cert_sig: "303d".into(),
                },
            }),
        });
        // An unavailable maker — no offer payload, but still appears.
        s.makers.push(ApiMaker {
            address: "127.0.0.1:7777".into(),
            state: ApiMakerState::Unavailable {
                reason: ApiUnavailableReason::NoOfferResponse,
                since_ts: Some(1_234_567_800),
                last_attempt_ts: Some(1_234_567_890),
                attempts: 3,
            },
            protocol: None,
            timestamp: 1_234_567_890,
            last_offer_update_ts: None,
            next_offer_check_ts: Some(1_234_568_000),
            offer: None,
        });
        // A banned maker with no offer at all.
        s.makers.push(ApiMaker {
            address: "127.0.0.1:8888".into(),
            state: ApiMakerState::Banned {
                reason: ApiBanReason::ProvenViolation,
                recorded_at_ts: 1_234_567_800,
            },
            protocol: None,
            timestamp: 1_234_567_890,
            last_offer_update_ts: None,
            next_offer_check_ts: None,
            offer: None,
        });
        s.last_sync = Some(1_700_000_000);
    }

    let guard = common::MarketdServerGuard::start(store);

    let resp = guard
        .agent
        .get(&guard.url("/api/makers"))
        .call()
        .expect("GET /api/makers");
    assert_eq!(resp.status(), 200);
    let makers: Value = resp.into_json().expect("makers JSON");
    let arr = makers.as_array().expect("array");
    assert_eq!(
        arr.len(),
        3,
        "banned and unavailable makers must be returned"
    );

    // Good maker
    let good = &arr[0];
    assert_eq!(good["address"], "127.0.0.1:6102");
    assert_eq!(good["state"]["kind"], "good");
    assert_eq!(good["protocol"], "taproot");
    assert_eq!(good["offer"]["name"], "Alice's Maker");
    assert_eq!(good["offer"]["base_fee"], 1000);
    assert_eq!(good["offer"]["fidelity_bond"]["amount"], 5_000_000);
    assert_eq!(
        good["offer"]["fidelity_bond"]["outpoint"]["txid"],
        "deadbeef"
    );

    // Unavailable maker — includes the reason and attempt count.
    let unavailable = &arr[1];
    assert_eq!(unavailable["state"]["kind"], "unavailable");
    assert_eq!(unavailable["state"]["reason"], "no_offer_response");
    assert_eq!(unavailable["state"]["attempts"], 3);
    assert!(
        unavailable["offer"].is_null(),
        "offer must be null for unavailable maker"
    );
    assert!(unavailable["protocol"].is_null());

    // Banned maker — includes the proven reason and record time.
    let banned = &arr[2];
    assert_eq!(banned["state"]["kind"], "banned");
    assert_eq!(banned["state"]["reason"], "proven_violation");
    assert!(banned["offer"].is_null());

    let resp = guard
        .agent
        .get(&guard.url("/api/health"))
        .call()
        .expect("GET /api/health");
    let body: Value = resp.into_json().expect("health JSON");
    assert_eq!(body["maker_count"], 3);
    assert_eq!(body["with_offer"], 1);
    assert_eq!(body["last_sync"], 1_700_000_000);
}
