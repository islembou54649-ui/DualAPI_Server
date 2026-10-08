# DualAPI_Server — Unified Quotex + Binolla API Server

Connects to **both Quotex and Binolla simultaneously**, keeping both connections alive independently.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│  Quotex (qx-websocket1______5.py)                   │
│  • connect_quotex + keepalive + auto_reconnect      │
│  • Payouts (92+ assets), candles, live prices       │
│  • Never sleeps (keepalive 5s + watchdog 20s)      │
│  Runs on its own ASYNC_LOOP thread                  │
└─────────────────────────────────────────────────────┘
                      ↓ (both alive simultaneously)
┌─────────────────────────────────────────────────────┐
│  Binolla (binolla_api.py)                           │
│  • HTTP login → JWT → WebSocket                     │
│  • keepalive_loop (3s) + jwt_refresh + watchdog     │
│  • Payouts (sentiment), candles, live prices        │
│  Runs on DualServer's event loop                    │
└─────────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────────┐
│  HTTP API (port 8766) + Interactive CLI             │
│  /api/quotex/*   /api/binolla/*   /api/dual/*       │
└─────────────────────────────────────────────────────┘
```

## Quick Start

```bash
# 1. Copy qx-websocket1______5.py from qxCANDAL411121 repo
cp ../qxCANDAL411121/qx-websocket1______5.py .

# 2. Install dependencies
pip install certifi requests websocket-client beautifulsoup4 fake-useragent orjson

# 3. Run the server
python DualServer.py \
  --qx-email you@quotex.com --qx-password secret \
  --bn-email you@binolla.com --bn-password secret

# 4. Or with saved credentials.json
python DualServer.py
```

## API Endpoints

### Health & Status
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Both platforms' connection status |
| GET | `/api/status` | Detailed status (payouts count, streaming count) |

### Quotex Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/quotex/payouts` | All Quotex payout rates |
| GET | `/api/quotex/payouts/<asset>` | Payout for one asset |
| GET | `/api/quotex/streaming` | List streaming assets |
| GET | `/api/quotex/last-tick?asset=X` | Live price |

### Binolla Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/binolla/payouts` | All Binolla payout rates |
| GET | `/api/binolla/payouts/<asset>` | Payout for one asset |
| GET | `/api/binolla/streaming` | List streaming assets |
| GET | `/api/binolla/last-tick?asset=X` | Live price |

### Dual (Combined) Endpoints
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/dual/payouts` | Compare payouts from both platforms |
| GET | `/api/dual/last-tick?asset=X` | Compare live prices from both platforms |

## Interactive CLI

```
dual> status
--- Quotex ---
  Connected:  True
  Payouts:    92
  Streaming:  3

--- Binolla ---
  Connected:  True
  Payouts:    45
  Streaming:  12

dual> dual payouts
ASSET                QUOTEX     BINOLLA
EURUSD_otc           85.0%      82%
GBPJPY_otc           84.0%      79%
...

dual> dual last-tick EURUSD_otc
  Asset: EURUSD_otc
  Quotex:  1.08564
  Binolla: 1.08561
```

## Files

| File | Description |
|------|-------------|
| `DualServer.py` | Main unified server (this file) |
| `binolla_api.py` | Binolla client (from API_server repo) |
| `qx-websocket1______5.py` | Quotex client (from qxCANDAL411121 repo) |
| `dual_server.db` | SQLite database (auto-created) |
| `credentials.json` | Saved credentials (auto-created) |
| `dual_server.log` | Server log file |
