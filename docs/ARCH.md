# marketd architecture

`marketd` is a thin HTTP service that turns the OpenSwap network's live offerbook
into a JSON API and serves a React dashboard on top. It is a **read-only**
aggregator, no swaps, no wallet operations, no maker-side logic. built on top
of the [`openswap`](https://github.com/citadel-foss/openswap) `Taker` SDK.

![Arch](./marketd-arch.png)

## What it does, in one paragraph

Browsers ask `marketd` for Signet or Mainnet maker snapshots. `marketd` keeps
both fresh by running two OpenSwap `Taker`s in the background. Each discovers
makers via Nostr, validates fidelity bonds against its own blockchain backend,
and fetches offers over Tor. Signet uses Bitcoin Core RPC/ZMQ; Mainnet uses
Electrum. The isolated results are cached in memory and served as JSON. The UI
is a Vite-built React SPA with a network toggle.

So most of `marketd`'s shape comes from the **dependencies it pulls in** rather
than from `marketd` itself: a Bitcoin node (RPC + REST + ZMQ), a Tor daemon
(SOCKS + control), Nostr relays for discovery, and Tor hidden-service makers.

## System boundaries

| Boundary                | Direction                          | Purpose                                                                                          |
| ----------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Browser <-> marketd** | bidirectional                      | Signet and Mainnet maker/health APIs, plus the SPA assets                                         |
| **marketd -> bitcoind** | outbound JSON-RPC + REST + ZMQ sub | Signet wallet init, blockchain info, fidelity bond UTXO checks                                    |
| **marketd -> Electrum** | outbound SSL, optionally via Tor   | Mainnet chain sync and fidelity bond validation                                                    |
| **marketd -> Tor**      | outbound (control + SOCKS5)        | Auth + circuit setup, then proxied connections to onion makers                                   |
| **marketd -> Nostr**    | outbound WSS                       | Subscribe to fidelity announcements (`kind=37777`) on `wss://nos.lol` and `wss://relay.damus.io` |
| **marketd -> makers**   | outbound, via Tor SOCKS5           | `GetOffer` request, receive `Offer` (fee schedule + fidelity bond)                               |

## Internal structure

`marketd` runs an HTTP server and **two independent sync threads**, each with
its own in-memory store and persisted OpenSwap data directory:

1. **HTTP server:** `tokio` async runtime with `axum`. Serves the SPA and both
   route groups. Reads from the selected store; never blocks on the network.
2. **Signet sync loop:** owns a Bitcoin Core-backed `Taker`.
3. **Mainnet sync loop:** owns an Electrum-backed `Taker`.

Each store is an `Arc<RwLock<MakerStore>>`. The HTTP thread takes a read lock
per request, and each sync thread takes a write lock only while publishing its
new maker snapshot.

`Taker::init` itself spawns more threads inside the sync thread's process: a
`Watcher` thread (consumes Bitcoin ZMQ events, runs Nostr discovery), and an
`OfferSyncService` (fetches offers from each discovered maker over Tor). We
treat these as opaque. `marketd` only calls `taker.run_offer_sync_now()` and
`taker.fetch_offers()`.

## Boot sequence

```
1. Parse CLI / env config (clap)
2. Spawn the Signet and Mainnet sync threads
3. Each thread waits for Tor; Signet also waits for Bitcoin Core RPC
4. Each thread initializes its Taker in an independent retry loop
5. Start the HTTP server (Docker listens on 0.0.0.0:3005)
```

The `wait_for_tcp` step is critical: it uses **only the first resolved socket
address** (`addr.to_socket_addrs().next()`), matching the behaviour of
`bitcoind::bitcoincore_rpc`'s `simple_http` transport. This avoids a subtle bug
where `localhost` resolves to `::1` first, the multi-address Rust stdlib
`TcpStream::connect` succeeds, but the JSON-RPC client only tries `::1`, fails,
and the wallet init dies with `ConnectionRefused`, even though "the port is
open".

---

## Sync cycle

Once a `Taker` is initialized, its sync thread runs:

```rust
loop {
    taker.sync_offerbook_and_wait()?;
    let book = taker.fetch_offers()?;
    let makers = book.all_makers()
        .iter()
        .map(|maker| ApiMaker::from_candidate(maker, timestamp))
        .collect();
    store.write().unwrap().makers = makers;
    thread::sleep(Duration::from_secs(cfg.sync_interval_secs));
}
```

The transformation `MakerOfferCandidate -> ApiMaker` is in `state.rs`. Good,
unavailable, and banned makers are all represented. Offers include the maker
name; an empty legacy name is serialized as `null`.

---

## API surface

```
GET /api/makers          -> Signet ApiMaker[] (Bitcoin Core)
GET /api/health          -> Signet health
GET /api/mainnet/makers  -> Mainnet ApiMaker[] (Electrum)
GET /api/mainnet/health  -> Mainnet health
GET /*                   -> SPA assets, with index.html as fallback
```

`ApiOffer` (see `state.rs`):

```jsonc
{
  "address": "<onion-host>:<port>",
  "timestamp": 1735689600,
  "base_fee": 100,
  "amount_relative_fee_pct": 0.1,
  "time_relative_fee_pct": 0.0005,
  "min_size": 10000,
  "max_size": 50000000,
  "required_confirms": 1,
  "minimum_locktime": 144,
  "tweakable_point": "<hex pubkey>",
  "fidelity_bond": {
    "amount": 50000,
    "outpoint": { "txid": "<hex>", "vout": 0 },
    "lock_time": 905000,
    "cert_hash": "<hex>",
    "cert_sig": "<hex DER>"
  }
}
```

---

## Deployment

Two containers use `network_mode: host`. Bitcoin Core is expected to already
be running on the VPS host:

| Service    | Image                  | Ports                           | Role                                            |
| ---------- | ---------------------- | ------------------------------- | ----------------------------------------------- |
| `tor`      | `osminogin/tor-simple` | 9050 (SOCKS), 9051 (control)    | Hashed control password                         |
| `marketd`  | this repo              | 3005 (HTTP)                     | Dual-network aggregator + SPA                   |

`docker compose up -d --build` brings up Tor and Marketd. `./run.sh prod` is an
interactive alternative for configuring the external Signet node, Mainnet
Electrum server, and Tor.

---

## What's deliberately NOT here

- **No wallet operations**, even though `Taker::init` creates a wallet file.
  The wallet is only needed to satisfy the `Taker` constructor — `marketd` never
  signs, spends, or holds keys you'd care about.
- **No swap logic.** OpenSwap execution and recovery APIs are unused.
- **No persistence beyond the offerbook.** `~/.openswap/marketd/offerbook.json`
  is written by `Taker`'s background service; `marketd` itself keeps no state.
- **No auth on `/api/*`.** It's a public read-only feed.
