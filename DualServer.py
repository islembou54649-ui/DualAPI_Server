#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DualServer — Unified Quotex + Binolla API Server
=================================================
Connects to BOTH Quotex and Binolla simultaneously:
  1. Quotex connection (via qx-websocket1______5.py — never sleeps)
  2. Binolla connection (via binolla_api.py — JWT auto-refresh + watchdog)

Both connections stay alive independently. The server provides a unified
HTTP API + interactive CLI to access data from both platforms.

Architecture:
  ┌─────────────────────────────────────────────────────┐
  │  Quotex (qx-websocket1______5.py)                   │
  │  • connect_quotex + keepalive + auto_reconnect      │
  │  • Payouts, candles, live prices                    │
  │  Runs on its own ASYNC_LOOP thread                  │
  └─────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────┐
  │  Binolla (binolla_api.py)                           │
  │  • HTTP login → JWT → WebSocket                     │
  │  • keepalive_loop + jwt_refresh_loop + watchdog     │
  │  • Payouts, candles, live prices                    │
  │  Runs on DualServer's event loop                    │
  └─────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────┐
  │  HTTP API (port 8766)                               │
  │  /api/quotex/*   — Quotex endpoints                 │
  │  /api/binolla/*  — Binolla endpoints                │
  │  /api/dual/*     — Combined endpoints               │
  └─────────────────────────────────────────────────────┘
  ┌─────────────────────────────────────────────────────┐
  │  Interactive CLI (qx> / bn> / dual>)                │
  └─────────────────────────────────────────────────────┘

Usage:
  python DualServer.py --qx-email you@example.com --qx-password secret \\
                       --bn-email you@binolla.com --bn-password secret

  Or with saved credentials:
  python DualServer.py
"""

import os
import sys
import json
import time
import asyncio
import sqlite3
import threading
import argparse
import logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# ==============================================================================
# PATH SETUP — both client modules must be in the same directory
# ==============================================================================
SERVER_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SERVER_DIR))

# ==============================================================================
# LOGGING
# ==============================================================================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(SERVER_DIR / "dual_server.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("DualServer")
logging.getLogger("werkzeug").setLevel(logging.ERROR)

# ==============================================================================
# IMPORT QUOTEX CLIENT (qx-websocket1______5.py)
# ==============================================================================
# The filename contains hyphens, so we use importlib.
import importlib.util

# Check if qx-websocket1______5.py exists
QX_MODULE_PATH = SERVER_DIR / "qx-websocket1______5.py"
qxws = None
if QX_MODULE_PATH.exists():
    try:
        _qx_spec = importlib.util.spec_from_file_location(
            "qx_websocket1______5", str(QX_MODULE_PATH))
        qxws = importlib.util.module_from_spec(_qx_spec)
        _qx_spec.loader.exec_module(qxws)
        logger.info("Quotex client module loaded (qx-websocket1______5.py)")
    except Exception as exc:
        logger.warning(f"Failed to load Quotex client: {exc}")
        qxws = None
else:
    logger.warning("qx-websocket1______5.py not found — Quotex support disabled")

# ==============================================================================
# IMPORT BINOLLA CLIENT (binolla_api.py)
# ==============================================================================
bn = None
try:
    import binolla_api
    logger.info("Binolla client module loaded (binolla_api.py)")
except Exception as exc:
    logger.warning(f"Failed to load Binolla client: {exc}")
    bn = None

# ==============================================================================
# DATABASE
# ==============================================================================
DB_PATH = SERVER_DIR / "dual_server.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""CREATE TABLE IF NOT EXISTS candles (
        platform TEXT, asset TEXT, timeframe INTEGER, time INTEGER,
        open REAL, high REAL, low REAL, close REAL,
        PRIMARY KEY (platform, asset, timeframe, time))""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS payouts (
        platform TEXT, asset TEXT PRIMARY KEY, payout REAL,
        display_name TEXT, open INTEGER, updated_at TEXT)""")
    cursor.execute("""CREATE TABLE IF NOT EXISTS server_state (
        key TEXT PRIMARY KEY, value TEXT)""")
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")


# ==============================================================================
# QUOTEX MANAGER (reuses QXServer logic)
# ==============================================================================
# Payouts cache for Quotex
_QX_PAYOUTS: Dict[str, Dict] = {}
_QX_PAYOUTS_LOCK = threading.RLock()
_QX_PAYOUTS_LAST_UPDATE = 0.0

_QX_BINARY_PENDING: Dict = {"event": None, "json": None, "num": 0, "buffers": []}


def _qx_parse_payouts(message) -> Dict[str, Dict]:
    """Parse Quotex instruments message → {asset: {payout, display_name, open}}."""
    payouts = {}

    def extract(item):
        if isinstance(item, dict):
            name = item.get("asset") or item.get("symbol") or item.get("name")
            p = item.get("profit") or item.get("payout")
            if name and p is not None:
                try:
                    return name, {"payout": float(p)*100 if float(p)<=1 else float(p),
                                  "display_name": name, "open": item.get("open")}
                except: pass
        elif isinstance(item, list) and len(item) >= 6:
            name = item[1] if isinstance(item[1], str) else None
            if name:
                name = name.replace("\n", "").strip()
            p = item[5] if len(item) > 5 else None
            is_open = item[14] if len(item) > 14 else None
            dn = str(item[2]).replace("\n", " ").strip() if len(item) > 2 and item[2] else name
            if name and p is not None:
                try:
                    return name, {"payout": float(p)*100 if float(p)<=1 else float(p),
                                  "display_name": dn, "open": bool(is_open) if is_open is not None else None}
                except: pass
        return None, None

    instruments = None
    if isinstance(message, dict):
        instruments = message.get("list") or message.get("instruments") or message.get("data")
    elif isinstance(message, list) and len(message) >= 2 and isinstance(message[1], (dict, list)):
        payload = message[1]
        instruments = payload.get("list") if isinstance(payload, dict) else payload

    if isinstance(instruments, dict):
        for name, info in instruments.items():
            if isinstance(info, dict):
                p = info.get("profit") or info.get("payout")
                if p:
                    try:
                        payouts[name] = {"payout": float(p)*100 if float(p)<=1 else float(p),
                                         "display_name": name, "open": info.get("open")}
                    except: pass
    elif isinstance(instruments, list):
        for item in instruments:
            name, info = extract(item)
            if name and info:
                payouts[name] = info
    return payouts


def _qx_on_instruments(message):
    global _QX_PAYOUTS_LAST_UPDATE
    payouts = _qx_parse_payouts(message)
    if not payouts:
        return
    with _QX_PAYOUTS_LOCK:
        _QX_PAYOUTS.update(payouts)
        _QX_PAYOUTS_LAST_UPDATE = time.time()
    logger.info(f"[Quotex] Payouts updated: +{len(payouts)} | total={len(_QX_PAYOUTS)}")


def _qx_install_hook():
    """Install payouts capture hook on Quotex WebSocket client."""
    if not qxws:
        return
    WSC = qxws.WebsocketClient
    orig_on_msg = WSC.on_message

    def patched_on_message(self, wss, msg):
        # Binary frame
        if isinstance(msg, (bytes, bytearray)):
            msg_bytes = bytes(msg)
            pending = _QX_BINARY_PENDING.get("event", "")
            if pending:
                _QX_BINARY_PENDING["event"] = None
                _QX_BINARY_PENDING["json"] = None
                _QX_BINARY_PENDING["num"] = 0
                _QX_BINARY_PENDING["buffers"] = []
            if len(msg_bytes) > 0 and msg_bytes[0] == 0x04:
                try:
                    payload_str = msg_bytes[1:].decode("utf-8", errors="ignore")
                    parsed = json.loads(payload_str)
                    # Use pending event name to identify the data
                    if pending and any(x in pending.lower() for x in ("instruments", "assets", "settings")):
                        _qx_on_instruments(parsed)
                except:
                    pass
            try:
                orig_on_msg(self, wss, msg)
            except:
                pass
            return
        # Text frame
        try:
            if isinstance(msg, str):
                msg_str = msg
                if msg_str not in ("2", "3", "41"):
                    # Check for 451- binary prefix
                    if msg_str.startswith("45") and "-" in msg_str[:6]:
                        try:
                            dash = msg_str.index("-", 2)
                            num = int(msg_str[2:dash])
                            parsed = json.loads(msg_str[dash+1:])
                            if isinstance(parsed, list) and parsed:
                                ev = str(parsed[0]).lower()
                                if any(x in ev for x in ("instruments", "assets", "settings")):
                                    _QX_BINARY_PENDING["event"] = parsed[0]
                                    _QX_BINARY_PENDING["json"] = parsed
                                    _QX_BINARY_PENDING["num"] = num
                                    _QX_BINARY_PENDING["buffers"] = []
                        except: pass
                    # Check for inline 42["instruments/list", {...}]
                    elif msg_str.startswith("42["):
                        try:
                            parsed = json.loads(msg_str[2:])
                            if isinstance(parsed, list) and len(parsed) >= 2:
                                ev = str(parsed[0]).lower()
                                if any(x in ev for x in ("instruments", "assets", "settings")):
                                    payload = parsed[1]
                                    if isinstance(payload, dict) and not payload.get("_placeholder"):
                                        _qx_on_instruments(payload)
                        except: pass
        except: pass
        try:
            orig_on_msg(self, wss, msg)
        except: pass

    WSC.on_message = patched_on_message
    logger.info("[Quotex] Payouts capture hook installed")


class QuotexManager:
    """Manages the Quotex connection using qx-websocket1______5.py."""

    def __init__(self, email: str, password: str):
        self.email = email
        self.password = password
        self._bg_scheduled = False

    async def connect(self) -> bool:
        if not qxws:
            logger.error("Quotex client not available")
            return False
        _qx_install_hook()
        logger.info(f"[Quotex] Connecting as {self.email}...")
        loop = getattr(qxws, "ASYNC_LOOP", None)
        if not loop or not loop.is_running():
            logger.error("[Quotex] ASYNC_LOOP not running")
            return False
        future = asyncio.run_coroutine_threadsafe(
            qxws.connect_quotex(self.email, self.password, force_fresh=True, max_attempts=3),
            loop)
        try:
            ok = await asyncio.get_running_loop().run_in_executor(
                None, lambda: future.result(timeout=300))
        except Exception as exc:
            logger.error(f"[Quotex] connect failed: {exc}")
            return False
        if not ok:
            logger.error("[Quotex] Connection failed")
            return False
        logger.info("[Quotex] Connected successfully")
        self._schedule_bg_tasks()
        return True

    def _schedule_bg_tasks(self):
        if self._bg_scheduled:
            return
        loop = getattr(qxws, "ASYNC_LOOP", None)
        if not loop or not loop.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(qxws.keepalive_loop(), loop)
            asyncio.run_coroutine_threadsafe(qxws.auto_reconnect(), loop)
            asyncio.run_coroutine_threadsafe(qxws.stale_message_watchdog(), loop)
            asyncio.run_coroutine_threadsafe(qxws.health_monitor(), loop)
            self._bg_scheduled = True
            logger.info("[Quotex] Background tasks scheduled (keepalive, auto_reconnect, watchdog, health)")
        except Exception as exc:
            logger.error(f"[Quotex] Failed to schedule bg tasks: {exc}")

    def is_alive(self) -> bool:
        c = getattr(qxws, "CLIENT", None)
        a = getattr(qxws, "CONNECTION_ALIVE", False)
        return bool(a and c and c.api and getattr(c.api.state, "check_accepted_connection", False))

    def get_payouts(self) -> Dict[str, Dict]:
        with _QX_PAYOUTS_LOCK:
            return dict(_QX_PAYOUTS)

    def get_payout(self, asset: str) -> Optional[Dict]:
        with _QX_PAYOUTS_LOCK:
            return _QX_PAYOUTS.get(asset)

    def start_stream(self, asset: str) -> bool:
        if not self.is_alive() or not qxws:
            return False
        qxws.PERIOD = 1
        qxws.PERIOD_SECONDS = 60
        _all = getattr(qxws, "ALL_STREAMING_ASSETS", [])
        for a in _all:
            if a.api_symbol == asset and a.streaming:
                return True
        try:
            obj = qxws.Asset(asset)
        except:
            return False
        if obj not in _all:
            _all.append(obj)
        loop = getattr(qxws, "ASYNC_LOOP", None)
        if not loop or not loop.is_running():
            return False
        try:
            obj.stream_task = asyncio.run_coroutine_threadsafe(qxws.realtime_stream(obj), loop)
            logger.info(f"[Quotex] Stream started for {asset}")
            return True
        except:
            return False

    def get_live_price(self, asset: str) -> Optional[Dict]:
        if not qxws:
            return None
        for a in getattr(qxws, "ALL_STREAMING_ASSETS", []):
            if a.api_symbol == asset and a.price > 0:
                try:
                    digits = a.digits(a.price)
                except:
                    digits = 5
                return {"price": float(a.price), "time": int(a.last_update_time or 0), "digits": digits}
        return None

    def get_streaming_assets(self) -> List[str]:
        if not qxws:
            return []
        return [a.api_symbol for a in getattr(qxws, "ALL_STREAMING_ASSETS", []) if a.streaming]

    def status(self) -> Dict:
        return {
            "connected": self.is_alive(),
            "email": self.email,
            "payouts_count": len(self.get_payouts()),
            "streaming_count": len(self.get_streaming_assets()),
            "last_payouts_update": _QX_PAYOUTS_LAST_UPDATE,
        }


# ==============================================================================
# BINOLLA MANAGER
# ==============================================================================
class BinollaManager:
    """Manages the Binolla connection using binolla_api.py."""

    def __init__(self, email: str, password: str, is_demo: bool = True):
        self.email = email
        self.password = password
        self.is_demo = is_demo
        self.client = None
        self._stop_event = None
        self._keepalive_task = None
        self._jwt_task = None
        self._watchdog_task = None

    async def connect(self) -> bool:
        if not bn:
            logger.error("Binolla client not available")
            return False
        logger.info(f"[Binolla] Logging in as {self.email}...")
        # HTTP login to get JWT
        args = {"email": self.email, "password": self.password, "is_demo": self.is_demo}
        token = await bn.auto_login(args)
        if not token:
            logger.error("[Binolla] Login failed")
            return False
        logger.info("[Binolla] JWT obtained, connecting WebSocket...")
        self.client = await bn.connect_binolla(token, is_demo=self.is_demo, max_attempts=3)
        if not self.client:
            logger.error("[Binolla] WebSocket connection failed")
            return False
        logger.info("[Binolla] Connected successfully")
        # Start background tasks
        self._stop_event = asyncio.Event()
        self._keepalive_task = asyncio.create_task(bn.keepalive_loop(self.client, self._stop_event))
        self._jwt_task = asyncio.create_task(bn.jwt_refresh_loop(self.client, args, self._stop_event))
        self._watchdog_task = asyncio.create_task(bn.watchdog_reconnect_loop(self.client, args, self._stop_event))
        logger.info("[Binolla] Background tasks started (keepalive, JWT refresh, watchdog)")
        return True

    def is_alive(self) -> bool:
        return bool(self.client and self.client.api and
                     getattr(self.client.api.state, "check_accepted_connection", False))

    def get_payouts(self) -> Dict[str, Dict]:
        if not self.client or not self.client.api:
            return {}
        result = {}
        for name, sent in self.client.api.assets_sentiment.items():
            payout = None
            if isinstance(sent, dict):
                payout = sent.get("sentiment", sent.get("payout", sent.get("profit")))
            if payout is not None:
                result[name] = {"payout": payout, "display_name": name, "open": None}
        return result

    def get_payout(self, asset: str) -> Optional[Dict]:
        return self.get_payouts().get(asset)

    def get_live_price(self, asset: str) -> Optional[Dict]:
        if not self.client or not self.client.api:
            return None
        q = self.client.api.assets_quotes.get(asset)
        if q and isinstance(q, dict):
            return {"price": float(q.get("price", 0)), "time": int(q.get("time", 0)), "digits": 5}
        return None

    def get_streaming_assets(self) -> List[str]:
        if not self.client or not self.client.api:
            return []
        return list(self.client.api.assets_quotes.keys())

    def status(self) -> Dict:
        return {
            "connected": self.is_alive(),
            "email": self.email,
            "payouts_count": len(self.get_payouts()),
            "streaming_count": len(self.get_streaming_assets()),
        }


# ==============================================================================
# UNIFIED HTTP API SERVER
# ==============================================================================
class DualRequestHandler(BaseHTTPRequestHandler):
    qx_manager: Optional[QuotexManager] = None
    bn_manager: Optional[BinollaManager] = None
    loop: Optional[asyncio.AbstractEventLoop] = None

    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()

    def _send_json(self, data, status=200):
        self._set_headers(status)
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"))

    def _send_error(self, msg, status=400):
        self._send_json({"error": msg}, status)

    def do_OPTIONS(self):
        self._set_headers(200)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        params = parse_qs(parsed.query)

        # === HEALTH ===
        if path == "/api/health":
            self._send_json({
                "status": "ok",
                "time": datetime.now(timezone.utc).isoformat(),
                "quotex_connected": self.qx_manager.is_alive() if self.qx_manager else False,
                "binolla_connected": self.bn_manager.is_alive() if self.bn_manager else False,
            })
            return

        # === STATUS ===
        if path == "/api/status":
            self._send_json({
                "quotex": self.qx_manager.status() if self.qx_manager else {},
                "binolla": self.bn_manager.status() if self.bn_manager else {},
            })
            return

        # === QUOTEX ENDPOINTS ===
        if path == "/api/quotex/payouts":
            self._send_json({"count": len(self.qx_manager.get_payouts()),
                             "payouts": self.qx_manager.get_payouts()})
            return

        if path.startswith("/api/quotex/payouts/"):
            asset = path.replace("/api/quotex/payouts/", "")
            info = self.qx_manager.get_payout(asset)
            if info:
                self._send_json({"asset": asset, **info})
            else:
                self._send_error(f"No payout for {asset}", 404)
            return

        if path == "/api/quotex/streaming":
            self._send_json({"assets": self.qx_manager.get_streaming_assets()})
            return

        if path == "/api/quotex/last-tick":
            asset = params.get("asset", [None])[0]
            if not asset:
                self._send_error("Missing 'asset'")
                return
            live = self.qx_manager.get_live_price(asset)
            self._send_json({"status": "OK" if live else "WAIT", "asset": asset,
                             **(live or {})})
            return

        # === BINOLLA ENDPOINTS ===
        if path == "/api/binolla/payouts":
            self._send_json({"count": len(self.bn_manager.get_payouts()),
                             "payouts": self.bn_manager.get_payouts()})
            return

        if path.startswith("/api/binolla/payouts/"):
            asset = path.replace("/api/binolla/payouts/", "")
            info = self.bn_manager.get_payout(asset)
            if info:
                self._send_json({"asset": asset, **info})
            else:
                self._send_error(f"No payout for {asset}", 404)
            return

        if path == "/api/binolla/streaming":
            self._send_json({"assets": self.bn_manager.get_streaming_assets()})
            return

        if path == "/api/binolla/last-tick":
            asset = params.get("asset", [None])[0]
            if not asset:
                self._send_error("Missing 'asset'")
                return
            live = self.bn_manager.get_live_price(asset)
            self._send_json({"status": "OK" if live else "WAIT", "asset": asset,
                             **(live or {})})
            return

        # === DUAL (COMBINED) ENDPOINTS ===
        if path == "/api/dual/payouts":
            qx = self.qx_manager.get_payouts()
            bn_p = self.bn_manager.get_payouts()
            # Merge: show both platforms side by side
            all_assets = set(qx.keys()) | set(bn_p.keys())
            merged = {}
            for a in all_assets:
                merged[a] = {
                    "quotex": qx.get(a),
                    "binolla": bn_p.get(a),
                }
            self._send_json({"count": len(merged), "payouts": merged})
            return

        if path == "/api/dual/last-tick":
            asset = params.get("asset", [None])[0]
            if not asset:
                self._send_error("Missing 'asset'")
                return
            qx_live = self.qx_manager.get_live_price(asset)
            bn_live = self.bn_manager.get_live_price(asset)
            self._send_json({"asset": asset, "quotex": qx_live, "binolla": bn_live})
            return

        self._send_error("Not found", 404)

    def log_message(self, *a):
        pass


def make_handler(qx_mgr, bn_mgr, loop):
    class H(DualRequestHandler):
        pass
    H.qx_manager = qx_mgr
    H.bn_manager = bn_mgr
    H.loop = loop
    return H


# ==============================================================================
# CREDENTIALS
# ==============================================================================
CREDS_FILE = SERVER_DIR / "credentials.json"


def load_creds() -> Dict:
    if CREDS_FILE.exists():
        try:
            return json.loads(CREDS_FILE.read_text())
        except:
            pass
    return {}


def save_creds(creds: Dict):
    try:
        CREDS_FILE.write_text(json.dumps(creds, indent=2))
    except:
        pass


# ==============================================================================
# INTERACTIVE CLI
# ==============================================================================
class DualCLI:
    HELP = """DualServer CLI commands:
  status                         Show connection status for both platforms
  qx assets                      List Quotex assets (payout% + price)
  qx payout [asset]              Quotex payout for all or one asset
  qx watch <asset>               Start Quotex live stream for asset
  qx streaming                   List Quotex streaming assets
  bn assets                      List Binolla assets (payout% + price)
  bn payout [asset]              Binolla payout for all or one asset
  bn streaming                   List Binolla streaming assets
  dual payouts                   Compare payouts from both platforms
  dual last-tick <asset>         Compare live prices from both platforms
  help                           Show this help
  quit                           Exit"""

    def __init__(self, qx_mgr, bn_mgr):
        self.qx = qx_mgr
        self.bn = bn_mgr

    def run(self):
        print("\n" + "=" * 60)
        print("DualServer Interactive CLI (Quotex + Binolla)")
        print("=" * 60)
        print("Type 'help' for commands.\n")
        while True:
            try:
                line = input("dual> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting...")
                break
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]
            if cmd == "quit" or cmd == "exit":
                print("Shutting down...")
                break
            elif cmd == "help":
                print(self.HELP)
            elif cmd == "status":
                qx_s = self.qx.status()
                bn_s = self.bn.status()
                print(f"\n--- Quotex ---")
                print(f"  Connected:  {qx_s['connected']}")
                print(f"  Email:      {qx_s['email']}")
                print(f"  Payouts:    {qx_s['payouts_count']}")
                print(f"  Streaming:  {qx_s['streaming_count']}")
                print(f"\n--- Binolla ---")
                print(f"  Connected:  {bn_s['connected']}")
                print(f"  Email:      {bn_s['email']}")
                print(f"  Payouts:    {bn_s['payouts_count']}")
                print(f"  Streaming:  {bn_s['streaming_count']}")
            elif cmd == "qx":
                self._handle_qx(args)
            elif cmd == "bn":
                self._handle_bn(args)
            elif cmd == "dual":
                self._handle_dual(args)
            else:
                print(f"Unknown command: {cmd}. Type 'help'.")

    def _handle_qx(self, args):
        if not args:
            print("Usage: qx <assets|payout|watch|streaming>")
            return
        sub = args[0].lower()
        if sub == "assets":
            payouts = self.qx.get_payouts()
            if not payouts:
                print("[Quotex] No assets. Wait for payouts refresh.")
                return
            print(f"\n{'DISPLAY':<24} {'SYMBOL':<16} {'PAYOUT':<8} {'STATUS':<8}")
            print("-" * 60)
            for name, info in sorted(payouts.items()):
                p = info.get("payout", 0)
                dn = info.get("display_name", name)
                is_open = info.get("open")
                st = "OPEN" if is_open else ("CLOSED" if is_open is False else "-")
                print(f"{dn[:24]:<24} {name:<16} {p:5.1f}%  {st:<8}")
            print(f"\nTotal: {len(payouts)} assets")
        elif sub == "payout":
            if len(args) > 1:
                info = self.qx.get_payout(args[1])
                if info:
                    print(f"{args[1]}: {info.get('payout', 0):.1f}%")
                else:
                    print(f"No payout for {args[1]}")
            else:
                payouts = self.qx.get_payouts()
                for name, info in sorted(payouts.items()):
                    print(f"  {name:<20} {info.get('payout', 0):5.1f}%")
        elif sub == "watch":
            if len(args) < 2:
                print("Usage: qx watch <asset>")
                return
            if self.qx.start_stream(args[1]):
                print(f"[Quotex] Streaming started for {args[1]}")
            else:
                print(f"[Quotex] Failed to start stream for {args[1]}")
        elif sub == "streaming":
            assets = self.qx.get_streaming_assets()
            if assets:
                for a in assets:
                    live = self.qx.get_live_price(a)
                    if live:
                        print(f"  {a:<20} {live['price']:.{live['digits']}f}")
                    else:
                        print(f"  {a:<20} (waiting...)")
            else:
                print("[Quotex] No assets streaming")

    def _handle_bn(self, args):
        if not args:
            print("Usage: bn <assets|payout|streaming>")
            return
        sub = args[0].lower()
        if sub == "assets" or sub == "payout":
            payouts = self.bn.get_payouts()
            if not payouts:
                print("[Binolla] No payout data. Run 'bn assets' on binolla_api.py first.")
                return
            for name, info in sorted(payouts.items()):
                print(f"  {name:<20} {info.get('payout', 0)}%")
            print(f"\nTotal: {len(payouts)} assets")
        elif sub == "streaming":
            assets = self.bn.get_streaming_assets()
            if assets:
                for a in assets:
                    live = self.bn.get_live_price(a)
                    if live:
                        print(f"  {a:<20} {live['price']:.5f}")
                    else:
                        print(f"  {a:<20} (waiting...)")
            else:
                print("[Binolla] No assets streaming")

    def _handle_dual(self, args):
        if not args:
            print("Usage: dual <payouts|last-tick>")
            return
        sub = args[0].lower()
        if sub == "payouts":
            qx = self.qx.get_payouts()
            bn_p = self.bn.get_payouts()
            all_assets = sorted(set(qx.keys()) | set(bn_p.keys()))
            print(f"\n{'ASSET':<20} {'QUOTEX':<10} {'BINOLLA':<10}")
            print("-" * 40)
            for a in all_assets:
                qx_p = qx.get(a, {}).get("payout", "-")
                bn_p_val = bn_p.get(a, {}).get("payout", "-")
                qx_str = f"{qx_p:.1f}%" if isinstance(qx_p, (int, float)) else "-"
                bn_str = f"{bn_p_val}%" if isinstance(bn_p_val, (int, float)) else "-"
                print(f"{a:<20} {qx_str:<10} {bn_str:<10}")
            print(f"\nTotal: {len(all_assets)} assets")
        elif sub == "last-tick":
            if len(args) < 2:
                print("Usage: dual last-tick <asset>")
                return
            asset = args[1]
            qx_live = self.qx.get_live_price(asset)
            bn_live = self.bn.get_live_price(asset)
            print(f"\n  Asset: {asset}")
            print(f"  Quotex:  {qx_live['price']:.{qx_live['digits']}f}" if qx_live else "  Quotex:  (not streaming)")
            print(f"  Binolla: {bn_live['price']:.5f}" if bn_live else "  Binolla: (not streaming)")


# ==============================================================================
# MAIN
# ==============================================================================
async def server_main(qx_email, qx_password, bn_email, bn_password, bn_is_demo, port, host):
    init_db()

    # Create managers
    qx_mgr = QuotexManager(qx_email, qx_password)
    bn_mgr = BinollaManager(bn_email, bn_password, is_demo=bn_is_demo)

    # Connect to Quotex first (non-blocking: if fails, continue)
    logger.info("=" * 60)
    logger.info("Connecting to Quotex...")
    logger.info("=" * 60)
    qx_ok = await qx_mgr.connect()
    if not qx_ok:
        logger.warning("Quotex connection failed — continuing with Binolla only")

    # Connect to Binolla (Quotex stays alive!)
    logger.info("=" * 60)
    logger.info("Connecting to Binolla (Quotex stays alive)...")
    logger.info("=" * 60)
    bn_ok = await bn_mgr.connect()
    if not bn_ok:
        logger.warning("Binolla connection failed — continuing with Quotex only")

    # Save credentials
    save_creds({
        "quotex": {"email": qx_email, "password": qx_password},
        "binolla": {"email": bn_email, "password": bn_password, "is_demo": bn_is_demo},
    })

    # Start HTTP server
    loop = asyncio.get_running_loop()
    handler = make_handler(qx_mgr, bn_mgr, loop)
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    httpd_thread.start()
    logger.info("=" * 60)
    logger.info(f"DualServer listening on http://{host}:{port}")
    logger.info("Endpoints:")
    logger.info("  GET  /api/health")
    logger.info("  GET  /api/status")
    logger.info("  GET  /api/quotex/payouts")
    logger.info("  GET  /api/quotex/payouts/<asset>")
    logger.info("  GET  /api/quotex/streaming")
    logger.info("  GET  /api/quotex/last-tick?asset=EURUSD_otc")
    logger.info("  GET  /api/binolla/payouts")
    logger.info("  GET  /api/binolla/payouts/<asset>")
    logger.info("  GET  /api/binolla/streaming")
    logger.info("  GET  /api/binolla/last-tick?asset=EURUSD_otc")
    logger.info("  GET  /api/dual/payouts")
    logger.info("  GET  /api/dual/last-tick?asset=EURUSD_otc")
    logger.info("=" * 60)

    # Start CLI in daemon thread
    cli = DualCLI(qx_mgr, bn_mgr)
    cli_thread = threading.Thread(target=cli.run, daemon=True, name="DualCLI")
    cli_thread.start()

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down...")
        httpd.shutdown()


def main():
    parser = argparse.ArgumentParser(description="DualServer - Unified Quotex + Binolla API Server")
    parser.add_argument("--qx-email", help="Quotex account email")
    parser.add_argument("--qx-password", help="Quotex account password")
    parser.add_argument("--bn-email", help="Binolla account email")
    parser.add_argument("--bn-password", help="Binolla account password")
    parser.add_argument("--bn-real", action="store_true", help="Use Binolla real account (default: demo)")
    parser.add_argument("--port", type=int, default=8766, help="HTTP server port (default: 8766)")
    parser.add_argument("--host", default="0.0.0.0", help="HTTP server host")
    args = parser.parse_args()

    # Load saved credentials
    creds = load_creds()
    qx_creds = creds.get("quotex", {})
    bn_creds = creds.get("binolla", {})

    qx_email = args.qx_email or qx_creds.get("email", "")
    qx_password = args.qx_password or qx_creds.get("password", "")
    bn_email = args.bn_email or bn_creds.get("email", "")
    bn_password = args.bn_password or bn_creds.get("password", "")
    bn_is_demo = not args.bn_real if args.bn_real else bn_creds.get("is_demo", True)

    if not qx_email or not qx_password:
        print("Quotex credentials required. Use --qx-email and --qx-password or save to credentials.json")
    if not bn_email or not bn_password:
        print("Binolla credentials required. Use --bn-email and --bn-password or save to credentials.json")
    if not (qx_email and qx_password and bn_email and bn_password):
        print("\nUsage: python DualServer.py --qx-email X --qx-password Y --bn-email Z --bn-password W")
        sys.exit(1)

    try:
        asyncio.run(server_main(qx_email, qx_password, bn_email, bn_password, bn_is_demo, args.port, args.host))
    except KeyboardInterrupt:
        print("\nServer stopped by user")


if __name__ == "__main__":
    main()
