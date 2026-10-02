# Marketd

Web interface for viewing OpenSwap market offers and monitoring the decentralized Bitcoin swap marketplace.

## Overview

Marketd provides a dashboard for the [OpenSwap Protocol](https://github.com/citadel-foss/openswap) - a decentralized atomic swap protocol for private Bitcoin transactions. View live market offers, maker node status, and network activity.

Marketd uses `MARKETD_WALLET_PASSWORD` for OpenSwap's required encrypted
wallet. `run.sh` defaults it to the configured Tor password; direct runs default
to `openswap` and should override it in production.

### Signet and Mainnet scanners

A single Marketd process runs two isolated OpenSwap takers at the same time:

- `GET /api/makers` and `GET /api/health` use the existing Signet Bitcoin Core
  RPC/ZMQ backend.
- `GET /api/mainnet/makers` and `GET /api/mainnet/health` use Mainnet Electrum.

The frontend network toggle switches between those two maker endpoints. The
two takers use separate data directories and wallet names so their offerbooks
and discovery state cannot mix.

The Mainnet scanner defaults to Blockstream's Electrum endpoint. Add
`--electrum-tor` when running Marketd directly to route Electrum through the
configured Tor SOCKS proxy:

```bash
cargo run -- \
  --electrum ssl://electrum.blockstream.info:50002 \
  --electrum-tor \
  --mainnet-wallet-name marketd-mainnet
```

The equivalent environment variables are:

```bash
MARKETD_ELECTRUM_URL=ssl://electrum.blockstream.info:50002
MARKETD_ELECTRUM_TOR=true
MARKETD_TOR_SOCKS_PORT=9050
MARKETD_MAINNET_WALLET_NAME=marketd-mainnet
```

The Docker Compose deployment enables `MARKETD_ELECTRUM_TOR` by default. The
Electrum server's genesis header determines the Bitcoin network. Electrum
does not provide full blocks, so maker discovery is performed through the
network-specific OpenSwap Nostr subscription; Electrum verifies the announced
fidelity bonds.

## Quick Start

### Prerequisites
- Rust (latest stable)
- Node.js (v16+)

### Run everything
```bash
docker compose up -d --build
```

This expects the Signet Bitcoin Core RPC and ZMQ endpoints to be available on
the VPS host at `127.0.0.1:38332` and `tcp://127.0.0.1:28332`. Their credentials
default to `signet` / `signetpass` and can be overridden with the environment
variables shown in `docker-compose.yml`. Open `http://<vps-host>:3005` after the
container starts.

For the interactive configuration helper instead:

```bash
chmod +x run.sh
./run.sh prod
```

### Manual setup
Backend:
```bash
cargo run
```

Frontend (in another terminal):
```bash
cd web
npm install
npm run dev
```

## Features

- **Live Market Data**: View available swap offers and fees
- **Maker Status**: Monitor online/offline maker nodes  
- **Network Stats**: Track liquidity and swap activity
- **Privacy First**: All communication over Tor



## Related

- [OpenSwap Protocol](https://github.com/citadel-foss/openswap) - Main implementation and protocol documentation

## License

MIT
### Offer cleanup

After each successful sync, marketd removes makers whose last successful offer
update was at least three days ago, regardless of maker state. Removal uses
OpenSwap's existing API, which updates the in-memory and persisted offerbook.
Removed entries are also omitted from the dashboard snapshot. Makers still
advertised in the discovery registry can be rediscovered on a later sync.
Records with no successful-update timestamp are left alone because their age
is unknown. Removal errors are logged.
