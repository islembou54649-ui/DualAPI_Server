#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DualServer — Unified Quotex + Binolla API Server (SINGLE FILE)
================================================================
Connects to BOTH Quotex and Binolla simultaneously in one file.
Each broker has its own separate assets, payouts, and prices.

Architecture:
  - Quotex: connect_quotex + keepalive + auto_reconnect + payouts + candles + live
  - Binolla: HTTP login → JWT → WS + keepalive + JWT refresh + watchdog + payouts + candles
  - HTTP API (port 8766): /api/quotex/* and /api/binolla/* (SEPARATE, not merged)
  - Interactive CLI: dual> prompt with qx/bn subcommands

Usage:
  python DualServer.py --qx-email X --qx-password Y --bn-email Z --bn-password W
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import ssl
import json
import time
import math
import struct
import logging
import asyncio
import calendar
import platform
import random
import re
import shutil
import threading
import traceback
import itertools
import configparser
import contextlib
from pathlib import Path
from datetime import datetime, timedelta
from collections import OrderedDict, defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Awaitable, Callable, Dict, Generic, Hashable, List, Literal, Mapping, Optional, Tuple, TypeVar

import certifi
import requests
import websocket
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from bs4.element import AttributeValueList
from fake_useragent import UserAgent

try:
    import orjson as _orjson
    HAS_ORJSON = True
except ImportError:
    _orjson = None
    HAS_ORJSON = False

# ==============================================================================
# WEB SERVER IMPORTS (Flask-based live chart dashboard)
# ==============================================================================
try:
    from flask import Flask, request as flask_request, Response, jsonify
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

# ==============================================================================
# SECTION 1: LOGGING & SSL SETUP
# ==============================================================================
def _prepare_logging():
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())
    websocket_logger = logging.getLogger("websocket")
    websocket_logger.setLevel(logging.INFO)
    websocket_logger.addHandler(logging.NullHandler())

_prepare_logging()
logger = logging.getLogger(__name__)

cert_path = certifi.where()
os.environ['SSL_CERT_FILE'] = cert_path
os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path
cacert = os.environ.get('WEBSOCKET_CLIENT_CA_BUNDLE')

ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
ssl_context.load_verify_locations(cert_path)


# ==============================================================================
# SECTION 1.5: EVENT-DRIVEN WAIT PRIMITIVES (replaces asyncio.sleep polling)
# ==============================================================================
# pyquotex._api._waits — " " .
# polling timeout asyncio.sleep
# asyncio.Event .

async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                      poll_interval: float = 0.05) -> None:
    """ predicate() poll_interval True timeout.

 asyncio.TimeoutError . :
 while not condition:
 await asyncio.sleep(X)
 latency X poll_interval (50ms ).
 """
    async def _loop():
        while not predicate():
            await asyncio.sleep(poll_interval)
    await asyncio.wait_for(_loop(), timeout=timeout)


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """ event index. TimeoutError .

 :
 for _ in range(100):
 if cond_a: return A
 if cond_b: return B
 await asyncio.sleep(0.1)
 """
    if not events:
        raise ValueError("wait_for_first_event requires at least one event")
    tasks = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout,
                                           return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        for i, t in enumerate(tasks):
            if t in done and t.result() and not t.cancelled():
                return i
        # timeout
        raise asyncio.TimeoutError()
    except asyncio.CancelledError:
        for t in tasks:
            if not t.done():
                t.cancel()
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    """ asyncio.Event thread ( websocket thread).

 run_coroutine_threadsafe coroutine 
 callback loop thread-safe loop.call_soon_threadsafe.
 """
    if event is None or loop is None:
        return
    try:
        if not loop.is_closed() and loop.is_running():
            loop.call_soon_threadsafe(event.set)
    except RuntimeError:
        # loop —
        pass


# ==============================================================================
# SECTION 2: CONSTANTS & SESSION
# ==============================================================================
USER_AGENT = "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0"
base_dir = Path.cwd()
session_lock = threading.Lock()

def resource_path(relative_path: str) -> Path:
    global base_dir
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        base_dir = Path(sys._MEIPASS)
    return base_dir / relative_path

def load_session(email: str, user_agent: str = None) -> dict:
    if user_agent is None:
        try: user_agent = UserAgent().random
        except Exception: user_agent = USER_AGENT
    output_file = Path(resource_path("session.json"))
    with session_lock:
        all_sessions = {}
        if output_file.exists():
            try: all_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError: pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        if email not in all_sessions:
            all_sessions[email] = {"cookies": None, "token": None, "user_agent": user_agent}
        output_file.write_text(json.dumps(all_sessions, indent=4))
        return all_sessions.get(email)

def update_session(email: str, d: dict) -> dict:
    output_file = Path(resource_path("session.json"))
    with session_lock:
        current_sessions = {}
        if output_file.exists():
            try: current_sessions = json.loads(output_file.read_text())
            except json.JSONDecodeError: pass
        else:
            output_file.parent.mkdir(exist_ok=True, parents=True)
        current_sessions[email] = d
        output_file.write_text(json.dumps(current_sessions, indent=4))
        return current_sessions.get(email)

# ==============================================================================
# SECTION 3: HTTP NAVIGATOR (PROVEN WORKING METHOD)
# ==============================================================================
retry_strategy = Retry(
    total=3, backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504, 104],
    allowed_methods=["HEAD", "POST", "PUT", "GET", "OPTIONS"],
)

class CipherSuiteAdapter(HTTPAdapter):
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections', '_pool_maxsize', '_pool_block', 'source_address']
    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket
        if self.server_hostname:
            self.ssl_context.server_hostname = self.server_hostname
        if self.cipherSuite:
            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(**kwargs)

    def wrap_socket(self, *args, **kwargs):
        if hasattr(self.ssl_context, 'server_hostname') and self.ssl_context.server_hostname:
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)

class Browser(Session):
    def __init__(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', 'prime256v1')
        self.cipherSuite = kwargs.pop('cipherSuite', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384')
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        self.headers.update(self.get_headers())
        self.mount('https://', CipherSuiteAdapter(ecdhCurve=self.ecdhCurve, cipherSuite=self.cipherSuite, server_hostname=self.server_hostname, source_address=self.source_address, ssl_context=ssl_context, max_retries=retry_strategy))

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): self.__exit__(exc_type, exc_val, exc_tb)

    def get_headers(self):
        self.default_headers = {"User-Agent": USER_AGENT}
        return self.default_headers

    def set_headers(self, headers=None):
        self.headers.update(self.default_headers)
        if headers: self.headers.update(headers)

    def get_cookies(self):
        return '; '.join(f'{i.name}={i.value}' for i in self.cookies)

    def get_soup(self):
        if self.response and not self.response.ok: raise RuntimeError(self.response.reason)
        return BeautifulSoup(self.response.content, "html.parser")

    def send_request(self, method, url, headers=None, **kwargs):
        merged_headers = self.headers.copy()
        if headers: merged_headers.update(headers)
        if self.proxies: kwargs['proxies'] = self.proxies
        self.response = self.request(method, url, headers=merged_headers, **kwargs)
        return self.response

# ==============================================================================
# SECTION 4: HTTP LOGIN & SETTINGS
# ==============================================================================
class Login(Browser):
    url = ""
    cookies = None
    ssid = None
    # FALLBACK default only - real value is set per-instance from api.host
    base_url = 'qxbroker.com'
    https_base_url = f'https://{base_url}'

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        # ---- DYNAMIC DOMAIN: follow the user-selected host -----------------
        # All HTTP login traffic now goes to the SAME domain that the WebSocket
        # will later connect to via ws2.<host>, so cookies/token stay valid.
        if not getattr(api, 'host', None):
            pass  # keep the hard-coded fallback
        else:
            self.base_url = api.host
            self.https_base_url = f'https://{self.base_url}'
        self.headers = self.get_headers()
        self.full_url = f"{self.https_base_url}/{api.lang}"

    def get_token(self):
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "pt-BR,pt;q=0.8,en-US;q=0.5,en;q=0.3"
        self.headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
        self.headers["Referer"] = f"{self.full_url}/sign-in"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Linux"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        self.send_request("GET", f"{self.full_url}/sign-in/modal/")
        html = self.get_soup()
        match = html.find("input", {"name": "_token"})
        return None if not match else match.get("value")

    async def awaiting_pin(self, data, input_message):
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Referer"] = f"{self.full_url}/sign-in/modal"
        data["keep_code"] = 1
        try:
            code = input(input_message)
            if not code.isdigit():
                print("Please enter a valid code.")
                await self.awaiting_pin(data, input_message)
            data["code"] = code
        except KeyboardInterrupt:
            print("\nClosing program.")
            sys.exit()
        await asyncio.sleep(1)
        self.send_request(method="POST", url=f"{self.full_url}/sign-in/modal", data=data)

    def get_profile(self):
        self.response = self.send_request(method="GET", url=f"{self.full_url}/trade")
        if self.response:
            script = self.get_soup().find_all("script", {"type": "text/javascript"})
            script = script[0].get_text() if script else "{}"
            match = script.strip().replace(";", "").replace("window.settings = ", "")
            self.cookies = self.get_cookies()
            try:
                settings_dict = json.loads(match)
                self.ssid = settings_dict.get("token")
            except json.JSONDecodeError:
                self.ssid = None
            self.api.session_data["cookies"] = self.cookies
            self.api.session_data["token"] = self.ssid
            self.api.session_data["user_agent"] = self.headers["User-Agent"]
            update_session(self.api.username, self.api.session_data)
            return self.response, settings_dict if self.ssid else None
        return None, None

    async def _post(self, data):
        self.response = self.send_request(method="POST", url=f"{self.full_url}/sign-in/", data=data)
        required_keep_code = self.get_soup().find("input", {"name": "keep_code"})
        if required_keep_code:
            auth_body = self.get_soup().find("main", {"class": "auth__body"})
            input_message = f'{auth_body.find("p").text}: ' if auth_body.find("p") else "Enter the PIN code sent to your email: "
            await self.awaiting_pin(data, input_message)
            await asyncio.sleep(1)
            return self.success_login()
        return self.success_login()

    def success_login(self):
        if "trade" in str(self.response.url):
            return True, "Login successful."
        soup = self.get_soup()
        not_available = soup.select_one("#tab-1 > div > div.modal-sign__not-avalible__title")
        if not_available: return False, f"Service unavailable: {not_available.get_text(strip=True)}"
        error = soup.select_one("#tab-1 form > div:nth-child(2) > div")
        msg = error.get_text(strip=True) if error else "Unknown error"
        return False, f"Login failed. {msg}"

    async def __call__(self, username, password, user_data_dir=None):
        data = {"_token": self.get_token(), "email": username, "password": password, "remember": 1}
        status, msg = await self._post(data)
        if status: self.get_profile()
        return status, msg

class Settings(Browser):
    def __init__(self, api):
        super().__init__()
        self.set_headers()
        self.api = api
        self.headers = self.get_headers()

    def get_settings(self):
        self.headers["content-type"] = "application/json"
        self.headers["referer"] = f"{self.api.https_url}/{self.api.lang}/trade"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        response = self.send_request("GET", f"{self.api.https_url}/api/v1/cabinets/digest")
        return response.json()

# ==============================================================================
# SECTION 5: WEBSOCKET CLIENT & STATE (SYNC + EVENT REGISTRY INTEGRATION)
# ==============================================================================
class WebsocketStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTED = 1
    CONNECTING = 2
    ERROR = -1

class AuthStatus(IntEnum):
    NOT_AUTHENTICATED = 0
    AUTHENTICATING = 1
    AUTHENTICATED = 2
    FAILED = -1

class ConnectionState:
    def __init__(self):
        self.SSID = None
        self.status = WebsocketStatus.DISCONNECTED
        self.auth_status = AuthStatus.NOT_AUTHENTICATED
        self.ssl_Mutual_exclusion = False
        self.ssl_Mutual_exclusion_write = False
        self.check_rejected_connection = False
        self.check_accepted_connection = False
        self.check_websocket_if_error = False
        self.check_websocket_if_connect = None
        self.websocket_error_reason = None

        # ===== EVENT-DRIVEN ADDITIONS =====
        # asyncio polling. lazily async context
        # init_events() "no running event loop" .
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        # loop websocket thread
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        """ loop . async context."""
        if self.ws_connected_event is None:
            self.ws_connected_event = asyncio.Event()
        if self.ws_closed_event is None:
            self.ws_closed_event = asyncio.Event()
        if self.auth_accepted_event is None:
            self.auth_accepted_event = asyncio.Event()
        if self.auth_rejected_event is None:
            self.auth_rejected_event = asyncio.Event()
        if self.ws_error_event is None:
            self.ws_error_event = asyncio.Event()
        try:
            self._loop = asyncio.get_running_loop()
        except RuntimeError:
            self._loop = None

    def reset_events(self) -> None:
        """ ."""
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.auth_accepted_event, self.auth_rejected_event,
                   self.ws_error_event):
            if ev is not None:
                ev.clear()

    # wrappers thread (websocket thread)
    def signal_ws_connected(self) -> None:
        _schedule_event_set(self.ws_connected_event, self._loop)

    def signal_ws_closed(self) -> None:
        _schedule_event_set(self.ws_closed_event, self._loop)

    def signal_auth_accepted(self) -> None:
        _schedule_event_set(self.auth_accepted_event, self._loop)

    def signal_auth_rejected(self) -> None:
        _schedule_event_set(self.auth_rejected_event, self._loop)

    def signal_ws_error(self) -> None:
        _schedule_event_set(self.ws_error_event, self._loop)

class WebsocketClient:
    def __init__(self, api):
        self.api = api
        self.state = api.state
        self.headers = {
            "User-Agent": self.api.session_data.get("user_agent", USER_AGENT),
            "Origin": self.api.https_url,
            "Host": f"ws2.{self.api.host}",
        }
        self.wss = websocket.WebSocketApp(
            self.api.wss_url,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
            header=self.headers,
            cookie=self.api.session_data.get("cookies"),
        )

    def on_message(self, wss, msg):
        self.state.ssl_Mutual_exclusion = True
        # ===== STALE-WATCHDOG: =====
        # watchdog .
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()
        except Exception:
            pass
        try:
            msg_str = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)

            if msg_str == "2":
                try:
                    self.wss.send("3")
                except Exception:
                    pass
                self.state.ssl_Mutual_exclusion = False
                return
            if msg_str == "3":
                self.state.ssl_Mutual_exclusion = False
                return

            if "authorization/reject" in msg_str:
                logger.warning("Token rejected.")
                self.state.check_rejected_connection = True
                self.state.auth_status = AuthStatus.FAILED
                # ===== EVENT-DRIVEN FIX =====
                self.state.signal_auth_rejected()
            elif "s_authorization" in msg_str:
                self.state.check_accepted_connection = True
                self.state.check_rejected_connection = False
                self.state.auth_status = AuthStatus.AUTHENTICATED
                self.state.status = WebsocketStatus.CONNECTED
                print("\n" + "="*60)
                print("Connected to server successfully")
                print("="*60 + "\n")
                # ===== EVENT-DRIVEN FIX =====
                self.state.signal_auth_accepted()

            message = None
            if len(msg_str) > 1 and msg_str[1] in ('[', '{'):
                try:
                    message = json.loads(msg_str[1:])
                except Exception:
                    pass

            if message is not None:
                self._process_message_and_raise_events(message)

            if str(msg_str) == "41":
                self.state.check_websocket_if_connect = 0
        except Exception as e:
            logger.error("Unhandled error in on_message: %s", e)
        self.state.ssl_Mutual_exclusion = False

    def _process_message_and_raise_events(self, message):
        try:
            loop = self.api._async_loop
            if loop is None or not loop.is_running():
                return

            if isinstance(message, dict):
                asset = message.get("asset")
                if asset and (message.get("candles") or message.get("data") or message.get("history")):
                    self.api.candle_v2_data[asset] = message
                    self.api.candles.candles_data = message.get("candles") or message.get("data") or message.get("history")

                    asyncio.run_coroutine_threadsafe(
                        self.api.event_registry.set_event(f'candles_ready_{asset}', message),
                        loop
                    )

                    index = message.get("index")
                    if index is not None:
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(f'candles_ready_{asset}_{index}', message),
                            loop
                        )

            if isinstance(message, dict) and (message.get("liveBalance") or message.get("demoBalance")):
                self.api.account_balance = message

            if isinstance(message, list) and len(message) > 0 and isinstance(message[0], list) and len(message[0]) == 4:
                asset = message[0][0]
                self.api.realtime_candles[asset] = message[0]
        except Exception as e:
            logger.debug(f"Error processing message: {e}")

    def on_error(self, wss, error):
        global CONNECTION_ALIVE
        logger.error(error)
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_error()
        try:
            CONNECTION_ALIVE = False
        except Exception:
            pass

    def on_open(self, wss):
        logger.info("Websocket client connected.")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTED
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_connected()
        asset_name = self.api.current_asset or "EURUSD"
        period = self.api.current_period or 60
        self.wss.send('42["tick"]')
        self.wss.send('42["indicator/list"]')
        self.wss.send('42["drawing/load"]')
        self.wss.send('42["pending/list"]')
        self.wss.send(f'42["instruments/update",{{"asset":"{asset_name}","period":{period}}}]')
        self.wss.send(f'42["depth/follow","{asset_name}"]')
        self.wss.send('42["chart_notification/get"]')
        self.wss.send('42["instruments/get"]')
        self.wss.send('42["tick"]')

    def on_close(self, wss, close_status_code, close_msg):
        global CONNECTION_ALIVE
        logger.info("Websocket connection closed.")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        # ===== EVENT-DRIVEN FIX =====
        self.state.signal_ws_closed()
        try:
            CONNECTION_ALIVE = False
        except Exception:
            pass

    def on_ping(self, wss, ping_msg): pass
    def on_pong(self, wss, pong_msg): pass

# ==============================================================================
# SECTION 6: QUOTEX API CORE
# ==============================================================================
class CandlesObj:
    def __init__(self): self.__candles_data = None
    @property
    def candles_data(self): return self.__candles_data
    @candles_data.setter
    def candles_data(self, candles_data): self.__candles_data = candles_data

class EventRegistry:
    def __init__(self):
        self._events: Dict[str, asyncio.Event] = {}
        self._data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def get_event(self, key: str) -> asyncio.Event:
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            return self._events[key]

    async def set_event(self, key: str, data: Any = None):
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            self._data[key] = data
            self._events[key].set()

    async def wait_event(self, key: str, timeout: float = 30.0) -> Any:
        event = await self.get_event(key)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._data.get(key)
        except asyncio.TimeoutError:
            return None

    async def clear_event(self, key: str):
        async with self._lock:
            if key in self._events:
                self._events[key].clear()
            if key in self._data:
                del self._data[key]

class QuotexAPI:
    def __init__(self, host, username, password, lang, proxies=None, user_data_dir="."):
        self.state = ConnectionState()
        self.trace_ws = False
        self.current_asset = None
        self.current_period = None
        self.account_balance = None
        self.account_type = 1
        self.instruments = None
        self.host = host
        self.https_url = f"https://{host}"
        self.wss_url = f"wss://ws2.{host}/socket.io/?EIO=3&transport=websocket"
        self.websocket_thread = None
        self.websocket_client = None
        self.username = username
        self.password = password
        self.proxies = proxies
        self.lang = lang
        self.user_data_dir = user_data_dir
        self.session_data = {}
        self.browser = Browser()
        self.browser.set_headers()
        self.settings = Settings(self)
        self.candles = CandlesObj()
        self.candle_v2_data = {}
        self.realtime_price = defaultdict(list)
        self.realtime_candles = {}
        self.event_registry = EventRegistry()
        self._async_loop: Optional[asyncio.AbstractEventLoop] = None
        self._temp_status = ""
        # ===== STALE-WATCHDOG ADDITION =====
        # WS . watchdog
        # .
        self.last_message_at: float = time.time()
        # ===== FIX 7: Rate Limiter ( ) =====
        # . rate limiter
        # keepalive + watchdog.
        # rate limiter (15ms = ~66 req/s) bursts .
        self._ws_send_times: list[float] = []
        self._ws_min_interval: float = 0.015  # 15ms ( )
        self._ws_max_per_window: int = 100    # 100 / ()
        self._ws_window: float = 1.0          # 1
        self._throttle_multiplier: float = 1.0  # = 1.0 ( auto-throttle)
        self._last_send_at: float = 0.0

    @property
    def login(self): return Login(self)

    def _apply_rate_limit(self) -> None:
        """ rate limiting WS — .

 - (_ws_min_interval * _throttle_multiplier)
 - (_ws_max_per_window / _throttle_multiplier)
 """
        now = time.time()
        # 1)
        min_interval = self._ws_min_interval * self._throttle_multiplier
        if self._last_send_at > 0:
            elapsed = now - self._last_send_at
            if elapsed < min_interval:
                time.sleep(min_interval - elapsed)
                now = time.time()
        # 2)
        window_size = self._ws_window * self._throttle_multiplier
        cutoff = now - window_size
        self._ws_send_times = [t for t in self._ws_send_times if t >= cutoff]
        # 3)
        if len(self._ws_send_times) >= self._ws_max_per_window:

            sleep_for = (self._ws_send_times[0] + window_size) - now
            if sleep_for > 0:
                time.sleep(sleep_for)
                now = time.time()
                cutoff = now - window_size
                self._ws_send_times = [t for t in self._ws_send_times if t >= cutoff]
        # 4)
        self._ws_send_times.append(now)
        self._last_send_at = now

    def increase_throttle(self, factor: float = 2.0, max_multiplier: float = 8.0) -> None:
        """ ( ).
 => => => .
 """
        new_multiplier = min(self._throttle_multiplier * factor, max_multiplier)
        if new_multiplier != self._throttle_multiplier:
            self._throttle_multiplier = new_multiplier
            logger.info(f" Throttle increased to {new_multiplier}x (rate limit stress)")

    def decrease_throttle(self, factor: float = 0.5, min_multiplier: float = 1.0) -> None:
        """ ( )."""
        new_multiplier = max(self._throttle_multiplier * factor, min_multiplier)
        if new_multiplier != self._throttle_multiplier:
            self._throttle_multiplier = new_multiplier
            logger.info(f" Throttle restored to {new_multiplier}x")

    def send_websocket_request(self, data, no_force_send=True):
        # ===== FIX: busy-wait -> sleep + try/finally =====
        if no_force_send:
            deadline = time.time() + 5.0  # 5s
            while (self.state.ssl_Mutual_exclusion or self.state.ssl_Mutual_exclusion_write):
                if time.time() > deadline:
                    # — . .
                    break
                time.sleep(0.001)  # `pass` — CPU
        # ===== FIX 6: rate limit =====
        # : heartbeat messages ("2" "42[\"tick\"]" "42[\"instruments/get\"]")
        # rate limit — keepalive.
        is_heartbeat = (
            data == "2" or
            data == '42["tick"]' or
            data == '42["instruments/get"]' or
            'pending/list' in data or
            'indicator/list' in data or
            'drawing/load' in data
        )
        if not is_heartbeat:
            try:
                self._apply_rate_limit()
            except Exception:
                # rate limiter
                pass
        self.state.ssl_Mutual_exclusion_write = True
        try:
            if self.websocket_client and self.websocket_client.wss:
                self.websocket_client.wss.send(data)
        finally:
            # ===== FIX: flag =====
            self.state.ssl_Mutual_exclusion_write = False

    def subscribe_realtime_candle(self, asset, period):
        self.realtime_price[asset] = []
        self.realtime_candles[asset] = {}
        data = f'42["instruments/update", {json.dumps({"asset": asset, "period": period})}]'
        return self.send_websocket_request(data)

    def follow_candle(self, asset):
        return self.send_websocket_request(f'42["depth/follow", {json.dumps(asset)}]')

    def chart_notification(self, asset):
        return self.send_websocket_request(f'42["chart_notification/get", {json.dumps({"asset": asset, "version": "1.0.0"})}]')

    def get_candles_ws(self, asset, index, time_val, offset, period):
        payload = {"asset": asset, "index": index, "time": time_val, "offset": offset, "period": period}
        data = f'42["history/load",{json.dumps(payload)}]'
        return self.send_websocket_request(data)

    async def authenticate(self):
        async with self.login as login:
            status, msg = await login(self.username, self.password, self.user_data_dir)
        if status:
            self.state.SSID = self.session_data.get("token")
        return status, msg

    async def start_websocket(self):
        self.state.check_websocket_if_connect = None
        self.state.check_websocket_if_error = False
        self.state.websocket_error_reason = None
        # ===== EVENT-DRIVEN FIX =====
        # +
        self.state.init_events()
        self.state.reset_events()
        # loop ( reconnect)
        try:
            self.state._loop = asyncio.get_running_loop()
        except RuntimeError:
            self.state._loop = None

        if not self.state.SSID:
            await self.authenticate()
        self.websocket_client = WebsocketClient(self)
        payload = {
            "suppress_origin": True, "ping_interval": 24, "ping_timeout": 20, "ping_payload": "2",
            "origin": self.https_url, "host": f"ws2.{self.host}",
            "sslopt": {"check_hostname": True, "cert_reqs": ssl.CERT_REQUIRED, "ca_certs": cacert, "context": ssl_context},
        }
        if platform.system() == "Linux":
            payload["sslopt"]["ssl_version"] = ssl.PROTOCOL_TLS
        self.websocket_thread = threading.Thread(target=self.websocket_client.wss.run_forever, kwargs=payload)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        # ===== EVENT-DRIVEN FIX =====
        # polling:
        # for _ in range(100):
        # if self.state.check_websocket_if_error: return False, ...
        # elif self.state.check_websocket_if_connect == 1: return True, ...
        # elif self.state.check_rejected_connection: return False, "Token Rejected."
        # await asyncio.sleep(0.1)
        # : connected, rejected, error, closed
        try:
            idx = await wait_for_first_event(
                self.state.ws_connected_event,
                self.state.auth_rejected_event,
                self.state.ws_error_event,
                self.state.ws_closed_event,
                timeout=10.0,
            )
        except asyncio.TimeoutError:
            return False, "Timeout waiting for websocket open"

        if idx == 0:
            return True, "Websocket connected successfully!!!"
        elif idx == 1:
            self.state.SSID = None
            return False, "Websocket Token Rejected."
        elif idx == 2:
            return False, self.state.websocket_error_reason or "Websocket error"
        elif idx == 3:
            return False, "Websocket connection closed."
        return False, "Unknown websocket state"

    async def send_ssid(self, timeout=10):
        if not self.state.SSID: return False
        # ===== EVENT-DRIVEN FIX =====
        # ( send_ssid start_websocket )
        if self.state.auth_accepted_event is None:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()

        payload = {"session": self.state.SSID, "isDemo": self.account_type, "tournamentId": 0}
        data = f'42["authorization",{json.dumps(payload)}]'
        self.send_websocket_request(data)

        # ===== EVENT-DRIVEN FIX =====
        # polling:
        # while not check_accepted and not check_rejected:
        # if time.time() - start_time > timeout: return False
        # await asyncio.sleep(0.5)
        # accepted rejected .
        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0  # True accepted, False rejected

    async def connect(self, is_demo):
        self.account_type = 1 if is_demo else 0
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket: return check_websocket, websocket_reason
        check_ssid = await self.send_ssid()
        if not check_ssid:
            await self.authenticate()
            if self.state.SSID: await self.send_ssid()
        return check_websocket, websocket_reason

    async def close(self):
        if self.websocket_client and self.websocket_client.wss:
            self.websocket_client.wss.close()
            await asyncio.sleep(1)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True

# ==============================================================================
# SECTION 7: QUOTEX STABLE API WITH FULL HISTORY MIXIN
# ==============================================================================
_request_counter = itertools.count(int(time.time() * 1000))

def group_by_period(data, period):
    grouped = defaultdict(list)
    for tick in data:
        timestamp = int(tick[0])
        timeframe = int(timestamp // period)
        grouped[timeframe].append(tick)
    return dict(grouped)

def calculate_candles(history, period):
    if not isinstance(history, list) or not history: return []
    grouped = group_by_period(history, period)
    candles = []
    for minute, ticks in grouped.items():
        open_price = ticks[0][1]
        close_price = ticks[-1][1]
        high_price = max(tick[1] for tick in ticks)
        low_price = min(tick[1] for tick in ticks)
        candle = {'time': minute * period, 'open': open_price, 'close': close_price, 'high': high_price, 'low': low_price, 'ticks': len(ticks)}
        candles.append(candle)
    return candles[:-1] if len(candles) > 1 else candles


# ===== FIX A: =====
# : calculate_candles "tick" [time, price]
# tick[1] open/high/low/close. Quotex
# "history/load" [time, open, close, high, low] (5 ).
# calculate_candles tick :
# open = high = low = close = open_price => !
# fill_gap_once => get_candles => prepare_candles.
# .
def _parse_raw_candles(raw_candles):
    """ WebSocket dicts OHLC .

 "history/load":
 1) [time, open, close, high, low] — Quotex (5 )
 2) [time, open, close, high, low, vol] — volume (6 )
 3) {"time", "open", "high", "low", "close", ...} — dict
 4) [time, price(, volume)] — tick ( )
 """
    if not raw_candles: return []
    parsed = []
    for c in raw_candles:
        try:
            if isinstance(c, dict) and 'time' in c:
                t = int(c.get('time', c.get('timestamp', 0)))
                o = float(c.get('open', 0) or 0)
                h = float(c.get('high', c.get('max', 0)) or 0)
                l = float(c.get('low', c.get('min', 0)) or 0)
                cl = float(c.get('close', c.get('c', 0)) or 0)
                v = int(c.get('volume', c.get('vol', 0)) or 0)
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 5:
                # Quotex WS: [time, open, close, high, low(, volume)]
                t = int(c[0])
                o = float(c[1])
                cl = float(c[2])
                h = float(c[3])
                l = float(c[4])
                v = int(c[5]) if len(c) >= 6 else 0
                if t > 0 and o > 0 and h > 0 and l > 0 and cl > 0:
                    parsed.append({'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v})
            elif isinstance(c, (list, tuple)) and len(c) >= 2:
                # tick format: [time, price(, volume)]
                t = int(c[0])
                p = float(c[1])
                v = int(c[2]) if len(c) >= 3 else 0
                if t > 0 and p > 0:
                    parsed.append({'time': t, 'open': p, 'high': p, 'low': p, 'close': p, 'volume': v})
        except (TypeError, ValueError):
            continue
    return parsed

def process_candles_v2(history, asset, data):
    if not history or not isinstance(history, dict): return data if data else []
    candles_data = history.get(asset, {})
    candles = candles_data.get("candles", [])[1:] if candles_data else []
    combined = candles + (data if data else [])
    if combined:
        candle_dict = {c.get('time'): c for c in combined if isinstance(c, dict) and 'time' in c}
        return list(candle_dict.values()) if candle_dict else []
    return combined

def merge_candles(candles_data):
    if not candles_data: return []
    candle_dict = {c['time']: c for c in candles_data if isinstance(c, dict) and 'time' in c}
    return sorted(candle_dict.values(), key=lambda x: x['time']) if candle_dict else []

class Quotex:
    def __init__(self, email=None, password=None, host="qxbroker.com", lang="en", proxies=None, user_data_dir="browser", asset_default="EURUSD", period_default=60):
        self.email = email
        self.password = password
        self.host = host
        self.lang = lang
        self.proxies = proxies
        self.user_data_dir = user_data_dir
        self.asset_default = asset_default
        self.period_default = period_default
        self.account_is_demo = 1
        self.codes_asset = {}
        self.api = None
        self.subscribe_candle = []
        self.subscribe_candle_all_size = []
        self.subscribe_mood = []
        session = load_session(self.email, USER_AGENT)
        self.session_data = session

    async def check_connect(self):
        if self.api is None: return False
        # ===== EVENT-DRIVEN FIX =====
        # :
        # await asyncio.sleep(1)
        # return self.api.state.check_accepted_connection == 1
        # . 2s 50ms
        # — latency 1000ms <100ms.
        try:
            await wait_until(
                lambda: self.api.state.check_accepted_connection == 1,
                timeout=2.0,
                poll_interval=0.05,
            )
            return True
        except asyncio.TimeoutError:
            return self.api.state.check_accepted_connection == 1

    async def connect(self):
        self.api = QuotexAPI(self.host, self.email, self.password, self.lang, proxies=self.proxies, user_data_dir=self.user_data_dir)
        self.api.session_data = self.session_data
        self.api.state.SSID = self.session_data.get("token")
        self.api._async_loop = asyncio.get_running_loop()
        if not self.session_data.get("token"):
            check, reason = await self.api.authenticate()
            if not check: return check, reason
        check, reason = await self.api.connect(self.account_is_demo == 1)
        if not check:
            self.session_data = {}
            return False, "Websocket connection rejected."
        return check, reason

    async def change_account(self, balance_mode: str):
        self.account_is_demo = 0 if balance_mode.upper() == "REAL" else 1
        self.api.account_type = self.account_is_demo
        payload = {"demo": self.api.account_type, "tournamentId": 0}
        self.api.send_websocket_request(f'42["account/change",{json.dumps(payload)}]')

    async def get_all_assets(self):
        return {}

    async def start_candles_stream(self, asset="EURUSD", period=60):
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.subscribe_realtime_candle(asset, period)
            self.api.chart_notification(asset)
            self.api.follow_candle(asset)

    async def get_realtime_candles(self, asset: str):
        if self.api: return self.api.realtime_candles.get(asset, [])
        return []

    async def get_candles(self, asset, end_from_time, offset, period, progressive=False, timeout=30, use_cache=False):
        if self.api is None: return None
        if end_from_time is None: end_from_time = time.time()
        index = calendar.timegm(time.gmtime())
        self.api.candles.candles_data = None
        await self.api.event_registry.clear_event(f'candles_ready_{asset}')
        await self.start_candles_stream(asset, period)
        self.api.get_candles_ws(asset, index, int(end_from_time), offset, period)
        try:
            history_data = await self.api.event_registry.wait_event(f'candles_ready_{asset}', timeout=timeout)
        except Exception:
            return None
        if history_data is None: return None
        candles = self.prepare_candles(asset, period, history_data)
        if progressive: return self.api.historical_candles.get("data", {})
        return candles

    async def _fetch_historical_batch(self, asset, fetch_time, offset, period, index, timeout):
        if self.api is None: return None
        payload = {"asset": asset, "index": index, "time": fetch_time, "offset": offset, "period": period}
        ws_msg = f'42["history/load",{json.dumps(payload)}]'
        event_name = f'candles_ready_{asset}_{index}'
        await self.api.event_registry.clear_event(event_name)
        self.api.send_websocket_request(ws_msg)
        try:
            return await self.api.event_registry.wait_event(event_name, timeout=timeout)
        except Exception:
            return None

    def _parse_historical_candles(self, raw_data):
        if raw_data is None: return []
        raw_candles = raw_data.get("data", []) or raw_data.get("candles", [])
        if not raw_candles: return []
        parsed = []
        for c in raw_candles:
            if isinstance(c, list) and len(c) >= 5:
                parsed.append({"time": int(c[0]), "open": float(c[1]), "close": float(c[2]), "high": float(c[3]), "low": float(c[4])})
            elif isinstance(c, dict) and "time" in c:
                parsed.append(c)
        return parsed

    async def get_historical_candles(self, asset, amount_of_seconds, period, timeout=30, max_workers=5, progress_callback=None):
        # ===== FIX 7: (5 workers + chunk=200) =====
        # .
        # (keepalive + watchdog ).
        max_workers = max_workers or 1
        chunk_seconds = period * FETCH_CHUNK_SIZE  # period * 200 = 12000s batch
        all_candles = {}
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t, end_t, worker_id):
            worker_candles = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures_in_worker = 0
                while oldest_t > end_t:
                    # ===== FIX 3: batch =====
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        # —
                        break
                    index = next(_request_counter)
                    batch_data = await self._fetch_historical_batch(asset, oldest_t, chunk_seconds, period, index, timeout)
                    if not batch_data:
                        oldest_t -= chunk_seconds
                        consecutive_failures_in_worker += 1
                        if consecutive_failures_in_worker >= 3:
                            # 3 consecutive failures = connection dead — exit
                            break
                        # backoff
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures_in_worker = 0
                    new_batch = self._parse_historical_candles(batch_data)
                    if not new_batch: oldest_t -= chunk_seconds; continue
                    batch_times = []
                    for c in new_batch:
                        ts = c['time']
                        if ts >= end_t and ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times: oldest_t -= chunk_seconds; continue
                    batch_times.sort()
                    new_oldest = batch_times[0]
                    if progress_callback: progress_callback(start_t - new_oldest, start_t - end_t, len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
                    # batches (0.1s — )
                    await asyncio.sleep(FETCH_BATCH_DELAY)
            return list(worker_candles.values())

        await self.start_candles_stream(asset, period)
        tasks = []
        for i in range(max_workers):
            s = current_time - (i * block_size)
            e = max(target_start_time, s - block_size)
            tasks.append(worker(s, e, i))
        results = await asyncio.gather(*tasks)
        for batch in results:
            for c in batch: all_candles[c['time']] = c
        return sorted(all_candles.values(), key=lambda x: x['time'])

    def prepare_candles(self, asset, period, history=None):
        if self.api is None: return []
        history_data = history if history is not None else self.api.candles.candles_data
        if history_data is None: return []
        if isinstance(history_data, dict):
            candles_list = history_data.get("candles") or history_data.get("data") or history_data.get("history") or []
        else:
            candles_list = history_data
        if not candles_list: return []
        # ===== FIX A: _parse_raw_candles calculate_candles =====
        # calculate_candles tick [time, price]
        # tick[1] open/high/low/close — (open == high ==
        # low == close) history/load
        # [time, open, close, high, low]. _parse_raw_candles
        # .
        candles_data = _parse_raw_candles(candles_list)
        # grill period ( )
        for c in candles_data:
            c['time'] = (int(c['time']) // period) * period
        candles_v2_data = process_candles_v2(self.api.candle_v2_data, asset, candles_data)
        return merge_candles(candles_v2_data)

    async def close(self):
        if self.api: return await self.api.close()
        return True

# ==============================================================================
# SECTION 8: MT4 WRITER & ASSETS (COMPLETE)
# ==============================================================================
os.environ['SSL_CERT_FILE'] = cert_path
os.environ['WEBSOCKET_CLIENT_CA_BUNDLE'] = cert_path

DEBUG_LOGS = False
def dbg(msg: str):
    if DEBUG_LOGS: print(f"  \033[2m   [debug] {msg}\033[0m")

LOG_FILE = Path("qxchart.log")
def _log_to_file(line: str):
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f: f.write(line + "\n")
    except Exception: pass

def logmsg(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    _log_to_file(line)
    # If live table is active, queue the message instead of printing directly
    # to avoid corrupting the redrawn table
    if '_STATUS_MESSAGES_QUEUE' in globals() and globals()['_STATUS_MESSAGES_QUEUE'] is not None:
        try:
            globals()['_STATUS_MESSAGES_QUEUE'].append(line)
            # keep last 5 messages
            if len(globals()['_STATUS_MESSAGES_QUEUE']) > 5:
                globals()['_STATUS_MESSAGES_QUEUE'] = globals()['_STATUS_MESSAGES_QUEUE'][-5:]
        except Exception:
            pass
    else:
        print(f"  \033[2m[{ts}]\033[0m {msg}")

def log_exception(context: str, exc: BaseException):
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    _log_to_file(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}")

def _thread_excepthook(args):
    log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook

def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt): sys.__excepthook__(exc_type, exc_value, exc_tb); return
    log_exception("main thread (top level)", exc_value)
sys.excepthook = _main_excepthook

class _NullHandler(logging.Handler):
    def emit(self, record): pass

@contextlib.contextmanager
def suppress_terminal_output():
    _loggers = [logging.getLogger(), logging.getLogger("pyquotex"), logging.getLogger("Quotex"), logging.getLogger("websockets"), logging.getLogger("websocket"), logging.getLogger("asyncio")]
    _old_levels = [(l, l.level, l.disabled) for l in _loggers]
    _old_handlers = [(l, list(l.handlers)) for l in _loggers]
    for l in _loggers:
        l.handlers = [_NullHandler()]; l.setLevel(logging.CRITICAL + 1); l.disabled = True
    with open(os.devnull, 'w') as devnull:
        old_stdout, old_stderr = sys.stdout, sys.stderr
        sys.stdout, sys.stderr = devnull, devnull
        try: yield
        finally:
            sys.stdout, sys.stderr = old_stdout, old_stderr
            for l, lvl, dis in _old_levels: l.setLevel(lvl); l.disabled = dis
            for l, hs in _old_handlers: l.handlers = hs

WINAPI_AVAILABLE = False
if platform.system() == "Windows":
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        WM_COMMAND = 0x0111
        MT4_REFRESH_CHART = 33324
        GA_ROOT = 2
        user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        user32.PostMessageW.restype = wintypes.BOOL
        user32.GetAncestor.argtypes = [wintypes.HWND, wintypes.UINT]
        user32.GetAncestor.restype = wintypes.HWND
        user32.IsWindowVisible.argtypes = [wintypes.HWND]
        user32.IsWindowVisible.restype = wintypes.BOOL
        user32.IsWindow.argtypes = [wintypes.HWND]
        user32.IsWindow.restype = wintypes.BOOL
        user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, wintypes.INT]
        user32.GetWindowTextW.restype = wintypes.INT
        user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
        user32.GetWindowTextLengthW.restype = wintypes.INT
        WINAPI_AVAILABLE = True
    except Exception: pass

_MT4_HWND = None
_MT4_HWND_LAST_SEARCH = 0
_LAST_GLOBAL_REFRESH = 0
_ENUM_PROC_REF = None

def find_mt4_window():
    global _MT4_HWND, _MT4_HWND_LAST_SEARCH, _ENUM_PROC_REF
    if not WINAPI_AVAILABLE: return None
    now = time.time()
    if _MT4_HWND and (now - _MT4_HWND_LAST_SEARCH < 30):
        if user32.IsWindow(_MT4_HWND): return _MT4_HWND
    _MT4_HWND = None
    _MT4_HWND_LAST_SEARCH = now
    found = []
    @ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
    def enum_callback(hwnd, lparam):
        if user32.IsWindowVisible(hwnd):
            length = user32.GetWindowTextLengthW(hwnd)
            if length > 0:
                buf = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buf, length + 1)
                if "MetaTrader 4" in buf.value or "MetaTrader4" in buf.value: found.append(hwnd)
                return False
        return True
    _ENUM_PROC_REF = enum_callback
    user32.EnumWindows(enum_callback, 0)
    _MT4_HWND = found[0] if found else None
    return _MT4_HWND

REFRESH_INTERVAL = 1.0
def refresh_mt4():
    global _LAST_GLOBAL_REFRESH
    if not WINAPI_AVAILABLE: return False
    now = time.time()
    if now - _LAST_GLOBAL_REFRESH < REFRESH_INTERVAL: return False
    _LAST_GLOBAL_REFRESH = now
    hwnd = find_mt4_window()
    if not hwnd: return False
    root = user32.GetAncestor(hwnd, GA_ROOT)
    target = root if root else hwnd
    user32.PostMessageW(target, WM_COMMAND, MT4_REFRESH_CHART, 0)
    return True

class Colors:
    GREEN = '\033[92m'; RED = '\033[91m'; BLUE = '\033[94m'; YELLOW = '\033[93m'
    CYAN = '\033[96m'; BOLD = '\033[1m'; DIM = '\033[2m'; RESET = '\033[0m'; CLEAR_LINE = '\033[K'
    # ===== ألوان إضافية مطلوبة للواجهة الجديدة (v3 UI) =====
    WHITE = '\033[97m'      # أبيض ساطع
    MAGENTA = '\033[95m'    # بنفسجي ساطع
    GRAY = '\033[90m'       # رمادي

def _current_period_label() -> str:
    # Subsecond labels
    if IS_SUBSECOND and SUBSECOND_LABEL:
        return SUBSECOND_LABEL
    if PERIOD >= 1440 and PERIOD % 1440 == 0:
        d = PERIOD // 1440
        return f"D{d}" if d > 1 else "D1"
    if PERIOD >= 60 and PERIOD % 60 == 0:
        h = PERIOD // 60
        return f"H{h}" if h > 1 else "H1"
    return f"M{PERIOD}"

def pretty_asset_name(symbol: str, period_label: str = None) -> str:
    if period_label is None:
        period_label = _current_period_label()
    base = symbol
    suffix = ""
    if base.upper().endswith("_OTC"):
        base = base[:-4]
        suffix = " · OTC"
    if len(base) == 6 and base.isalpha():
        pretty = f"{base[:3].upper()}/{base[3:].upper()}{suffix}"
    else:
        pretty = f"{base.upper()}{suffix}"
    return f"({pretty}),{period_label}"

user_home = os.path.expanduser('~')
MT4_CONFIG_FILE = Path("mt4_config.json")
# ===== FIX J: digits — =====
# : " " —
# .
# mt4_digits.json:
# {
# "global_digits": null, // null = ; ( 5)
# "overrides": {
# "USDIDR-OTC": 4,
# "USDPKR-OTC": 5
# }
# }
DIGITS_CONFIG_FILE = Path("mt4_digits.json")
_digits_config_cache = None
_digits_config_loaded = False

def load_digits_config() -> dict:
    """ mt4_digits.json . ."""
    global _digits_config_cache, _digits_config_loaded
    try:
        if DIGITS_CONFIG_FILE.exists():
            mtime = DIGITS_CONFIG_FILE.stat().st_mtime
            if not _digits_config_loaded or _digits_config_cache.get('_mtime', 0) < mtime:
                _digits_config_cache = json.loads(DIGITS_CONFIG_FILE.read_text())
                _digits_config_cache['_mtime'] = mtime
                _digits_config_loaded = True
        elif _digits_config_loaded:
            # —
            _digits_config_cache = None
            _digits_config_loaded = False
    except Exception:
        return {}
    return _digits_config_cache if _digits_config_cache else {}

def _resolve_digits(symbol: str, price: float = 0.0) -> int:
    """ .
 
 :
 1) per-asset mt4_digits.json ("overrides")
 2) mt4_digits.json ("global_digits")
 3) ( )
 
 (FIX J):
 - JPY: 3 ()
 - < 0.5: 6 (was 6) — BRLUSD
 - < 1: 5 (was 5)
 - < 5: 5 (was 5)
 - < 10: 4 (was 4)
 - < 50: 4 (was 4)
 - < 100: 3 (was 3)
 - < 1000: 3 (was 2) ← FIX J: 100-1000
 - < 10000: 3 (was 2) ← FIX J
 - >= 10000: 3 (was 2) ← FIX J
 : >= 100 digits=2 (min grid 0.01) — .
 : >= 100 digits=3 (min grid 0.001) — 
 mt4_digits.json.
 """
    sym_upper = symbol.upper()
    # 1) per-asset override
    cfg = load_digits_config()
    if cfg:
        overrides = cfg.get('overrides', {}) or {}
        if sym_upper in overrides:
            try:
                d = int(overrides[sym_upper])
                if 0 <= d <= 8:
                    return d
            except (TypeError, ValueError):
                pass
        # 2) global override
        global_d = cfg.get('global_digits', None)
        if global_d is not None:
            try:
                d = int(global_d)
                if 0 <= d <= 8:
                    return d
            except (TypeError, ValueError):
                pass
    # 3) auto calculation (improved FIX J defaults)
    if "JPY" in sym_upper: return 3
    if price and price > 0:
        if price < 0.5:  return 6
        if price < 1:    return 5
        if price < 5:    return 5
        if price < 10:   return 4
        if price < 50:   return 4
        if price < 100:  return 3
        # FIX J: >= 100 digits=3 ( 2)
        # → (0.001 0.01)
        return 3
    # fallback when no price
    if any(x in sym_upper for x in ["IDR", "COP", "ARS", "NGN", "PKR", "DZD", "EGP", "MXN", "PHP", "INR", "BDT", "ZAR", "BRL"]):
        return 3  # FIX J: was 2
    return 5
SYSTEM_FOLDERS = {"default", "downloads", "mailbox", "signals", "symbolsets", "deleted", "templates", "profiles", "mql4", "logs", "config", "history_backup"}

def _validate_mt4_path(path: str) -> bool:
    if not path or not os.path.exists(path): return False
    try:
        test_file = os.path.join(path, ".write_test.tmp")
        with open(test_file, 'w') as f: f.write("test")
        os.remove(test_file)
        return True
    except Exception: return False

def _save_mt4_path(path: str):
    try:
        config = json.loads(MT4_CONFIG_FILE.read_text()) if MT4_CONFIG_FILE.exists() else {}
        config["mt4_history_path"] = path
        config["saved_at"] = int(time.time())
        MT4_CONFIG_FILE.write_text(json.dumps(config, indent=2))
    except Exception: pass

def find_mt4_history_path() -> str:
    appdata = os.environ.get('APPDATA', '') or os.environ.get('HOME', '')
    common_path = os.path.join(appdata, 'MetaQuotes', 'Terminal', 'Common', 'Files', 'qx_hst')
    try:
        os.makedirs(common_path, exist_ok=True)
        return common_path
    except Exception:
        pass
    
    base_terminal = os.path.join(user_home, "AppData", "Roaming", "MetaQuotes", "Terminal")
    if not os.path.exists(base_terminal): return ""
    all_servers = []
    try:
        for terminal_id in os.listdir(base_terminal):
            history_path = os.path.join(base_terminal, terminal_id, "history")
            if not os.path.exists(history_path): continue
            for server_name in os.listdir(history_path):
                server_lower = server_name.lower()
                if server_lower in SYSTEM_FOLDERS or server_lower.startswith(".") or server_lower.startswith("_"): continue
                server_path = os.path.join(history_path, server_name)
                if not os.path.isdir(server_path): continue
                try:
                    hst_files = [f for f in os.listdir(server_path) if f.endswith('.hst')]
                    all_servers.append({"terminal_id": terminal_id, "server_name": server_name, "full_path": server_path, "has_hst": len(hst_files) > 0, "hst_count": len(hst_files), "is_writable": _validate_mt4_path(server_path)})
                except Exception: pass
    except Exception: pass
    if not all_servers: return ""
    if MT4_CONFIG_FILE.exists():
        try:
            saved_path = json.loads(MT4_CONFIG_FILE.read_text()).get("mt4_history_path", "")
            if saved_path and os.path.exists(saved_path):
                for srv in all_servers:
                    if srv["full_path"] == saved_path and srv["is_writable"]: return saved_path
        except Exception: pass
    writable_servers = [s for s in all_servers if s["is_writable"]]
    if not writable_servers: return ""
    servers_with_hst = [s for s in writable_servers if s["has_hst"]]
    if servers_with_hst:
        servers_with_hst.sort(key=lambda x: (-x["hst_count"], x["server_name"]))
        chosen = servers_with_hst[0]
        _save_mt4_path(chosen["full_path"])
        return chosen["full_path"]
    chosen = writable_servers[0]
    _save_mt4_path(chosen["full_path"])
    return chosen["full_path"]

MT4_HISTORY_PATH = find_mt4_history_path()
if not MT4_HISTORY_PATH:
    MT4_HISTORY_PATH = os.path.join(user_home, "Desktop", "MT4_History_Fallback")
    os.makedirs(MT4_HISTORY_PATH, exist_ok=True)

SESSION_FILE = Path("session.json")
SESSION_STATE_FILE = Path("session_state.json")
EMAIL_FILE = Path("saved_email.txt")

class SessionManager:
    def __init__(self): self.state = self._load_state()
    def _load_state(self) -> dict:
        try:
            if SESSION_STATE_FILE.exists(): return json.loads(SESSION_STATE_FILE.read_text())
        except Exception: pass
        return {"last_login": 0, "last_success": False, "failed_auth_count": 0, "email": "", "host": "qxbroker.com"}
    def _save_state(self):
        try: SESSION_STATE_FILE.write_text(json.dumps(self.state, indent=2))
        except Exception: pass
    def should_force_fresh(self) -> bool:
        if not self.state.get("last_success", False): return True
        if self.state.get("failed_auth_count", 0) >= 2: return True
        if time.time() - self.state.get("last_login", 0) > 7 * 24 * 3600: return True
        return False
    def record_success(self, email: str, host: str = None):
        # FIX K:
        update_dict = {"last_login": time.time(), "last_success": True, "failed_auth_count": 0, "email": email}
        if host: update_dict["host"] = host
        self.state.update(update_dict)
        self._save_state()
        EMAIL_FILE.write_text(email)
    def record_failure(self, error: str):
        self.state["last_login"] = time.time()
        self.state["last_success"] = False
        self.state["failed_auth_count"] = self.state.get("failed_auth_count", 0) + 1
        self._save_state()
    def get_saved_email(self) -> str:
        email = self.state.get("email", "")
        return email if email else (EMAIL_FILE.read_text().strip() if EMAIL_FILE.exists() else "")

    def get_saved_host(self) -> str:
        # FIX K:
        return self.state.get("host", "qxbroker.com")
    @staticmethod
    def delete_session_file():
        if SESSION_FILE.exists():
            try: SESSION_FILE.unlink(); return True
            except Exception: pass
        return False
    @staticmethod
    def delete_browser_dir():
        browser_dir = Path("browser")
        if browser_dir.exists():
            try: shutil.rmtree(browser_dir, ignore_errors=True); return True
            except Exception: pass
        return False

session_manager = SessionManager()

# ==============================================================================
# UPDATED ASSET LIST & CANDLE COUNT SETTINGS
# ==============================================================================
ASSET_LIST = [
    "BRLUSD_otc", "USDARS_otc", "USDBDT_otc", "USDCOP_otc", "USDEGP_otc",
    "USDIDR_otc", "USDINR_otc", "USDMXN_otc", "USDNGN_otc", "USDPHP_otc",
    "USDPKR_otc", "USDZAR_otc", "AUDCAD_otc", "AUDCHF_otc", "AUDJPY_otc",
    "AUDNZD_otc", "AUDUSD_otc", "CADCHF_otc", "CADJPY_otc", "CHFJPY_otc",
    "EURAUD_otc", "EURCAD_otc", "EURCHF_otc", "EURGBP_otc", "EURJPY_otc",
    "EURNZD_otc", "EURUSD_otc", "GBPAUD_otc", "GBPCAD_otc", "GBPCHF_otc",
    "GBPJPY_otc", "GBPNZD_otc", "GBPUSD_otc", "NZDCAD_otc", "NZDCHF_otc",
    "NZDJPY_otc", "NZDUSD_otc", "USDCAD_otc", "USDCHF_otc", "USDDZD_otc", "USDJPY_otc",
]

TIMEFRAMES = [
    (1,    60,      "M1  - 1 minute",      False),
    (2,    120,     "M2  - 2 minutes",     False),
    (3,    180,     "M3  - 3 minutes",     False),
    (5,    300,     "M5  - 5 minutes",     False),
    (10,   600,     "M10 - 10 minutes",    False),
    (15,   900,     "M15 - 15 minutes",    False),
    (30,   1800,    "M30 - 30 minutes",    False),
    (60,   3600,    "H1  - 1 hour",        False),
    (240,  14400,   "H4  - 4 hours",       False),
    (1440, 86400,   "D1  - 1 day",         False),
    # Subsecond timeframes (aggregated locally from realtime ticks, no history API)
    (1,    5,       "S5  - 5 seconds",     True),
    (1,    10,      "S10 - 10 seconds",    True),
    (1,    15,      "S15 - 15 seconds",    True),
    (1,    30,      "S30 - 30 seconds",    True),
]

PERIOD = 1
PERIOD_SECONDS = 60
# Subsecond mode globals — set when user chooses S5/S10/S15/S30
IS_SUBSECOND = False
SUBSECOND_SECONDS = 0   # 5, 10, 15, or 30
SUBSECOND_LABEL = ""    # "5S", "10S", "15S", "30S"
SUBSECOND_MAX_CANDLES = 500  # v8.1: raised from 200 -> 500 to match SUBSECOND_HISTORY_CANDLES (user asked: keep >=500 5s candles in memory)
SUBSECOND_HISTORY_CANDLES = 500  # fetch up to 500 historical subsecond candles at startup (was 1000, reduced for speed)
# Semaphore to limit concurrent subsecond history fetches (3 at a time, not 41)
# Created lazily on first use to avoid event loop binding issues at import time
_SUBSECOND_FETCH_SEMAPHORE = None
# v8.1: explicit asset-to-asset delay for subsecond mode (user asked: ~1 second between currencies)
SUBSECOND_ASSET_DELAY = 2.0   # v8.3: raised from 1.0 -> 2.0 (server needs more breathing room between assets)
# v8.3: target fewer 1s candles -- the server throttles after ~5 chunks per asset, so 2.0x margin
# was pointless (we'd never reach it anyway). 1.3x targets 3250 1s = enough for 500 5s after dedup.
SUBSECOND_FETCH_MARGIN = 1.3  # v8.3: was 2.0 -- reduced to lower request count per asset
SUBSECOND_MAX_CHUNKS = 5      # v8.3: was 60 -- 5 chunks * 500s = 2500s = exactly 500 5s candles; more is wasted
# v8.3: user explicitly asked -- if the server returns >=85 5s candles from the first chunk, do not
# keep repeating the requests. Accept the server's per-asset history limit and move on.
SUBSECOND_EARLY_EXIT_CANDLES = 85  # stop fetching more chunks once we have >=85 aggregated 5s candles
# v8.3: graceful stop -- after this many consecutive zero-candle assets, the WebSocket is dead.
# Break the startup loop cleanly instead of burning 8 * 30s = 240s in reconnect attempts.
SUBSECOND_MAX_ZERO_STREAK = 3  # was effectively infinite (relied on MAX_RECONNECTS_DURING_FETCH=8)
# v8.4/v8.6: NEW feature for M1 timeframe -- fetch 1s candles first, aggregate
# to 1m, use them as the most granular bridge between the historical 1m fetch
# and the live stream. Disables the old _bridge_fetch_recent_candles for M1.
#
# v8.6 change: switched from 5s aggregation -> 1s aggregation. 1s is the most
# granular source -- if the server's 1s data is continuous, the aggregated 1m
# candle has NO gaps (60 consecutive 1s candles -> 1 perfect 1m candle). With
# 5s aggregation, a missing 5s candle leaves a partial gap in the 1m candle.
M1_USE_1S_BRIDGE = True       # set False to fall back to the old M1 bridge fetch
M1_1S_BRIDGE_TARGET = 750     # v8.6: target 1s candles for the bridge (=> ~12 1m candles)
M1_BRIDGE_TIMEOUT = 30        # seconds, bounded wait for the 1s fetch
# v8.11: delays to prevent server throttling in M1 bridge mode.
# User explicitly asked: "مهلات لكي لا لا يتوقف السرفر" (delays so the
# server doesn't stop). The pattern per asset is:
#   1s fetch -> M1_INTRA_ASSET_DELAY -> 1000 historical fetch -> M1_ASSET_DELAY -> next asset
M1_INTRA_ASSET_DELAY = 1.0    # v8.11: delay between 1s fetch and 1000 historical fetch (same asset)
M1_ASSET_DELAY = 1.0          # v8.11: delay between assets in M1 bridge mode (was 0.1s)
# v8.13: cap the bridge to the NEWEST N candles only, then REPLACE matching
# historical candles. User explicitly asked: "نربط 6 شموع الاولى فقط" (only
# bridge the first 6). The max gap between live stream and historical is 5
# candles, so 6 bridge candles guarantee full coverage. The server returns
# a variable count of 1s candles (8/12/13), so we always take the last 6.
M1_BRIDGE_REPLACE_COUNT = 6   # v8.13: only the newest N bridge candles replace historical
# v8.7: TEST MODE -- when True, for M1 timeframe, SKIP the 1000 historical
# 1m fetch entirely and display ONLY the 1s->1m aggregated candles on the chart.
# This lets us verify that the 1s aggregation produces valid 1m candles that MT4
# can render correctly. Once verified, set False to restore the full flow
# (historical 1000 1m + 1s->1m bridge merged).
# v8.10: TEST MODE disabled -- full flow is now active:
#   1) fetch 1s candles -> aggregate to 1m (8-13 bridge candles, no gaps)
#   2) fetch 1000 historical 1m candles via fetch_candles_with_retry
#   3) merge: [1000 historical] + [bridge where ts > last historical ts]
#   4) the bridge fills the 4-5 missing candles between historical and live
# Set to True to re-enter TEST MODE (1s->1m only, no historical fetch).
M1_TEST_1S_ONLY = False       # v8.10: TEST MODE disabled, full flow active
# ===== FIX 4: 1000 ( ) =====
# 500 1000 (4s).
# : workers=5 + chunk=200 ( ) .
INITIAL_CANDLES = 1000
MIN_CANDLES_THRESHOLD = 100
HISTORY_DAYS = 0.75
FETCH_DURATION_SECONDS = int(86400 * HISTORY_DAYS)
# v9.0: STREAM_POLL_INTERVAL reduced from 0.15s -> 0.05s for fastest possible tick updates.
# This is the loop inside realtime_stream / subsecond_stream that polls CLIENT.api.realtime_candles.
# Lower = faster live tick rendering on the chart.
STREAM_POLL_INTERVAL = 0.05
# v9.0: WRITE_HST_FILES_ENABLED = False — server no longer writes .hst files to disk.
# The web dashboard (Flask) is now the ONLY output channel. This eliminates disk I/O
# overhead and lets the bot run faster. Set to True if you still want HST files (e.g.,
# for MT4 direct loading). When False, asset.write() and MT4_WRITER.write_to_file() are no-ops.
WRITE_HST_FILES_ENABLED = False
# ===== FIX 4: WRITE_INTERVAL = 0.5s 3.0s ( 500ms) =====
WRITE_INTERVAL = 0.5
STALE_DATA_TIMEOUT = 180
STALE_RATIO_TRIGGER = 0.8
# ===== FIX 7: KEEPALIVE_PING_INTERVAL = 5s =====
# : " ".
# 10s (5 workers × 41 )
# keepalive . 5s .
KEEPALIVE_PING_INTERVAL = 5
RECONNECT_CHECK_INTERVAL = 1
RECONNECT_BASE_DELAY = 2
RECONNECT_MAX_DELAY = 30
STATUS_REFRESH_INTERVAL = 0.5
# ===== FIX 7: watchdog =====
# .
# STALE_MESSAGE_TIMEOUT=45s + STALE_WATCHDOG_INTERVAL=5s
# => latency = 45-50s ( )
# FIX 7: STALE_MESSAGE_TIMEOUT=20s + STALE_WATCHDOG_INTERVAL=3s
# => latency = 20-23s ( ~2x)
STALE_MESSAGE_TIMEOUT = 20
STALE_WATCHDOG_INTERVAL = 3  # 3s (was 5s)
ENGINEIO_PING_INTERVAL = 20  # "2" (engine.io ping) 20s — Socket.IO EIO=3
# ===== FIX 4: 4s 1000 =====
# ( 4s 1000 ):
# max_workers=5, chunk=period*200 (12000s), delay=0.1s
# : :
# - FETCH_ASSET_DELAY (0.1s)
# - workers ( FIX 3)
# - exponential backoff retry ( FIX 3)
# - main loop ( FIX 3)
# : 4s + ( FIX 1+2 )
FETCH_MAX_WORKERS = 5          # 5 workers (reverted — 10 caused connection drops)
FETCH_CHUNK_SIZE = 200         # 200 candles per batch (reverted)
FETCH_BATCH_DELAY = 0.1        # 0.1s between batches (reverted)
FETCH_ASSET_DELAY = 0.1        # 0.1s between assets (reverted)
# ===== FIX 7: cooldown — =====
FETCH_COOLDOWN_EVERY = 0       # 0 =
FETCH_COOLDOWN_DURATION = 0.0  # 0 =
FETCH_TIMEOUT = 30             # 30s per batch (reverted)
RETRY_BACKOFF_BASE = 2         # exponential backoff base
RETRY_BACKOFF_MAX = 15         # max delay between retries (reverted)
MAX_FETCH_RETRIES = 5          # 5 attempts (reverted)

MAX_RECONNECTS_DURING_FETCH = 8
# ===== FIX L1: gap fill 120 () 20 =====
# : " "
# 20 (20 ) 20 — .
# 120 () /.
GAP_FILL_CANDLES = 10  # fetch 10 recent candles to replace incomplete ones
# ===== FIX L1: 5 ( ) =====
# : _gap_filled = True => .
# : GAP_FILL_REFRESH_INTERVAL .
GAP_FILL_REFRESH_INTERVAL = 300  # 5

# ==============================================================================
# ===== BRIDGE FETCH (سد فجوة 4-5 شموع بين التاريخي والبث المباشر) =====
# ==============================================================================
# المشكلة: بعد انتهاء الجلب التاريخي (الذي يستغرق 5-15 ثانية)، يكون البث قد بدأ
#   لكن الخادم يؤجل إرسال ticks بسبب ضغط طلبات history/load. النتيجة: فجوة 4-5 شموع.
# الحل: بعد اكتمال الجلب التاريخي، اطلب آخر شموع تنتهي عند time.time() الحالي
#   (وليس T0). هذا يملأ الفجوة بين آخر شمعة تاريخية وأول شمعة بث مباشر.
# الأمان:
#   - BRIDGE_FETCH_ENABLED=False يُعطّل الميزة فوراً دون أي تأثير جانبي
#   - كل الأعمدة محاطة بـ try/except (الخطأ لا يُكسر الجلب التاريخي)
#   - Semaphore يمنع إرهاق الخادم بطلبات جسر متزامنة
#   - يستخدم get_candles الموجودة (دالة مُجرّبة وآمنة)
BRIDGE_FETCH_ENABLED = True       # مفتاح التشغيل/الإيقاف الرئيسي
BRIDGE_FETCH_CANDLES = 15         # عدد الشموع لجلب الجسر (يكفي لفجوة كبيرة + هامش أمان)
BRIDGE_FETCH_TIMEOUT = 20         # مهلة الجلب الجسري (ثانية) — زادت من 15 إلى 20
BRIDGE_FETCH_SEMAPHORE_LIMIT = 2  # أقصى عدد طلبات جسر متزامنة (لمنع إرهاق الخادم)
_BRIDGE_FETCH_SEMAPHORE = None    # يُنشأ تلقائياً عند أول استخدام (lazy init)

# ===== FIX L2: — =====
# : _is_dst time.altzone/time.timezone
# Windows ( DST
# DST — Africa/Algiers).
# : / HST → MT4.
# : datetime.now().astimezone().utcoffset() ( )
# .
try:
    from datetime import datetime as _dt_naive
    _SYSTEM_TZ_OFFSET = int(_dt_naive.now().astimezone().utcoffset().total_seconds())
except Exception:
    _SYSTEM_TZ_OFFSET = -time.timezone  # fallback ( )
# ===== " " : =====
# :
# LOCAL_TZ_OFFSET_SECONDS = 3600 # UTC+1 ( )
# LOCAL_TZ_OFFSET_SECONDS = 0 # UTC ( )
# LOCAL_TZ_OFFSET_SECONDS = 7200 # UTC+2 ( )
# LOCAL_TZ_OFFSET_SECONDS = 10800 # UTC+3 ( )
# None .
LOCAL_TZ_OFFSET_SECONDS = None  # None = _SYSTEM_TZ_OFFSET

def _get_tz_offset() -> int:
    """ (UTC → ). ."""
    if LOCAL_TZ_OFFSET_SECONDS is not None:
        return LOCAL_TZ_OFFSET_SECONDS
    return _SYSTEM_TZ_OFFSET

def _align_time(raw_ts: int, period_seconds: int = None) -> int:
    """Aligns a raw timestamp to period boundary after applying TZ offset.

 period_seconds=None reads PERIOD_SECONDS global dynamically (multi-timeframe support).
 """
    if period_seconds is None:
        period_seconds = PERIOD_SECONDS
    tz = _get_tz_offset()
    return ((int(raw_ts) + tz) // period_seconds) * period_seconds

# Fill missing slots with flat candles. max_gap=1440 (full day) allows filling
# gaps up to 1 day. period_seconds=None reads PERIOD_SECONDS dynamically.
def _fill_missing_slots(candles: list, period_seconds: int = None,
                        max_gap: int = 1440) -> list:
    """Fills time gaps between candles with flat candles (previous close).

 - Added candles have volume=0 (marked synthetic).
 - max_gap: max number of periods to fill (1440 = 1 day for M1).
 - period_seconds=None reads PERIOD_SECONDS dynamically (multi-timeframe).
 """
    if period_seconds is None:
        period_seconds = PERIOD_SECONDS
    if len(candles) < 2:
        return list(candles)
    candles = sorted(candles, key=lambda x: x['time'])
    out = [dict(candles[0])]
    for i in range(1, len(candles)):
        prev = out[-1]
        curr = candles[i]
        gap = (curr['time'] - prev['time']) // period_seconds
        if 0 < gap <= max_gap:

            slot = prev['time'] + period_seconds
            while slot < curr['time']:
                out.append({
                    'time': slot,
                    'open': prev['close'],
                    'high': prev['close'],
                    'low': prev['close'],
                    'close': prev['close'],
                    'volume': 0,
                })
                slot += period_seconds
        out.append(dict(curr))
    return out

# Aggregate 1-second candles into target_period (5s, 10s, 15s, 30s) candles.
# Used for sub-60s timeframes: fetch period=1 from server, aggregate locally.
def _aggregate_sub_minute(candles: list, target_period: int) -> list:
    """Aggregate 1-second candles into target_period candles.

    For each group of (target_period) consecutive 1s candles:
    - time = first candle's time aligned to target_period boundary
    - open = first candle's open
    - high = max of all highs
    - low = min of all lows
    - close = last candle's close
    - volume = sum of all volumes
    """
    if not candles or target_period <= 1:
        return list(candles)
    candles = sorted(candles, key=lambda x: x['time'])
    buckets = OrderedDict()
    for c in candles:
        bucket_time = (c['time'] // target_period) * target_period
        if bucket_time not in buckets:
            buckets[bucket_time] = {
                'time': bucket_time,
                'open': c['open'],
                'high': c['high'],
                'low': c['low'],
                'close': c['close'],
                'volume': int(c.get('volume', 0) or 0),
            }
        else:
            b = buckets[bucket_time]
            b['high'] = max(b['high'], c['high'])
            b['low'] = min(b['low'], c['low'])
            b['close'] = c['close']
            b['volume'] += int(c.get('volume', 0) or 0)
    return list(buckets.values())

# ===== FIX K: Quotex =====
# Domain list. Labels are intentionally NEUTRAL (no country/region labels) so
# no user feels singled out. Just the domain name as the broker publishes it.
DOMAINS = [
    ("qxbroker.com",    "qxbroker.com"),
    ("market-qx.info",  "market-qx.info"),
]
# — session_state
QX_HOST = "qxbroker.com"

ASYNC_LOOP = None
ASYNC_ENGINE_GENERATION = 0
_ENGINE_READY = threading.Event()
CONNECTION_ALIVE = False
CLIENT = None
EMAIL = None
PASSWORD = None
RECONNECTING = False
ALL_STREAMING_ASSETS = []
LAST_HEALTH_CHECK = 0
HEALTH_CHECK_INTERVAL = 20
# ===== FIX B: =====
# : " ".
# —
# 1000 .
LAST_CONNECTION_DROP_TIME = 0            # 0 =
LONG_DISCONNECT_THRESHOLD = 3600        # 3600s = 1
# ===== FIX F: =====
# mt4_gap_filler print()
# 0.5s →
# . : .
GAP_FILL_SUMMARY = ""  # ( mt4_gap_filler)
_STATUS_MESSAGES_QUEUE = []  # queue for log messages during live table (avoid corrupting redraw)
GAP_FILL_ACTIVE = False  # True

def _asyncio_loop_exception_handler(loop, context):
    exc = context.get("exception")
    if exc: log_exception(f"asyncio loop (gen {ASYNC_ENGINE_GENERATION})", exc)

def start_async_engine():
    global ASYNC_LOOP, ASYNC_ENGINE_GENERATION, CONNECTION_ALIVE
    while True:
        try:
            ASYNC_ENGINE_GENERATION += 1
            gen = ASYNC_ENGINE_GENERATION
            new_loop = asyncio.new_event_loop()
            new_loop.set_exception_handler(_asyncio_loop_exception_handler)
            asyncio.set_event_loop(new_loop)
            ASYNC_LOOP = new_loop
            _ENGINE_READY.set()
            if gen > 1:
                logmsg(f"[AsyncEngine] event loop recreated (gen {gen}). Rescheduling tasks...")
                CONNECTION_ALIVE = False
                asyncio.run_coroutine_threadsafe(health_monitor(), ASYNC_LOOP)
                asyncio.run_coroutine_threadsafe(auto_reconnect(), ASYNC_LOOP)
                asyncio.run_coroutine_threadsafe(keepalive_loop(), ASYNC_LOOP)
                # ===== FIX: stale watchdog loop =====
                asyncio.run_coroutine_threadsafe(stale_message_watchdog(), ASYNC_LOOP)
                for asset in ALL_STREAMING_ASSETS:
                    asset.stream_task = None
                    asset.streaming = False
            new_loop.run_forever()
        except Exception as e:
            log_exception(f"AsyncEngine (gen {ASYNC_ENGINE_GENERATION})", e)
            CONNECTION_ALIVE = False
            time.sleep(1)

async_thread = threading.Thread(target=start_async_engine, daemon=True, name="AsyncEngine")
async_thread.start()
_ENGINE_READY.wait(timeout=10)

class Asset:
    @staticmethod
    def _derive_mt4_symbol(raw_symbol: str) -> str:
        s = raw_symbol.strip()
        is_otc = s.upper().endswith("_OTC")
        if is_otc:
            base = s[:-4].upper()
            if PERIOD_SECONDS < 60:
                # Sub-minute: compact name "AUDUSDOTC5S" (11 chars, fits 12-byte header)
                result = f"{base}OTC{SUBSECOND_LABEL}"
            else:
                result = f"{base}-OTC"
        else:
            if PERIOD_SECONDS < 60:
                result = f"{s.upper()}{SUBSECOND_LABEL}"
            else:
                result = s.upper()
        return result[:12] if result else raw_symbol.upper()[:12]

    def __init__(self, symbol):
        self.api_symbol = symbol
        self.symbol = self._derive_mt4_symbol(symbol)
        self.period = PERIOD
        self.price = 0.0
        self.previous_price = 0.0
        # For sub-minute: filename = {symbol}1.hst (e.g., AUDUSD-5S1.hst)
        # symbol is "AUDUSD-5S" (compact, fits 12-byte HST header)
        # For 60s+: filename = {symbol}{PERIOD}.hst (e.g., AUDUSD-OTC5.hst)
        if PERIOD_SECONDS < 60:
            self.path = os.path.join(MT4_HISTORY_PATH, f"{self.symbol}1.hst")
        else:
            self.path = os.path.join(MT4_HISTORY_PATH, f"{self.symbol}{PERIOD}.hst")
        self.candles = []
        self.last_write = 0.0
        self.updates = 0
        self.streaming = False
        self.stream_task = None
        self.last_update_time = 0
        self.last_saved_close = 0.0
        self.last_saved_candle_time = 0
        self.last_saved_candle_count = 0
        self.dirty = False
        self._gap_filled = False

    def digits(self, price: float = None) -> int:
        # FIX J: _resolve_digits ( mt4_digits.json)
        p = price if price is not None else self.price
        return _resolve_digits(self.symbol, p or 0.0)

    def has_new_data(self):
        if not self.candles: return False
        c = self.candles[-1]
        return (c['close'] != self.last_saved_close or c['time'] != self.last_saved_candle_time or len(self.candles) != self.last_saved_candle_count)

    def mark_dirty(self): self.dirty = True

    def write(self, force=False):
        # v9.0: skip HST writing entirely when WRITE_HST_FILES_ENABLED is False.
        # The web dashboard (Flask) is the only output channel.
        if not WRITE_HST_FILES_ENABLED:
            return False
        if not force and not self.has_new_data(): return False
        temp = self.path + ".tmp"
        # For sub-minute timeframes, write period=1 (M1) in the header so MT4 opens it
        header_period = 1 if PERIOD_SECONDS < 60 else self.period
        try:
            with open(temp, 'wb') as f:
                f.write(struct.pack('<i', 400))
                f.write(b"(C)opyright 2003, MetaQuotes Software Corp.".ljust(64, b'\0'))
                f.write(self.symbol.encode('ascii').ljust(12, b'\0')[:12])
                f.write(struct.pack('<i', header_period))
                first_price = self.candles[0]['close'] if self.candles else self.price
                f.write(struct.pack('<i', self.digits(first_price)))
                f.write(struct.pack('<i', int(time.time())))
                f.write(struct.pack('<i', int(time.time())))
                f.write(b'\0' * 52)
                for c in self.candles:
                    f.write(struct.pack('<i', c['time']))
                    f.write(struct.pack('<d', c['open']))
                    f.write(struct.pack('<d', c['low']))
                    f.write(struct.pack('<d', c['high']))
                    f.write(struct.pack('<d', c['close']))
                    f.write(struct.pack('<q', int(c.get('volume', 0))))
            # ===== FIX 4: WinError 5 (Access Denied) + WinError 32 =====
            # WinError 32. WinError 5 (Access Denied)
            # MT4 ( ).
            # : retry WinError 5 + 32 + fallback.
            def _is_lock_error(err_str):
                err_str = err_str.lower()
                return (
                    "winerror 32" in err_str or
                    "used by another process" in err_str or
                    "winerror 5" in err_str or
                    "access denied" in err_str or
                    "accès refusé" in err_str or
                    "acces refusé" in err_str or
                    "permission" in err_str
                )
            replaced = False
            for attempt in range(8):  # 8 5
                try:
                    os.replace(temp, self.path)
                    replaced = True
                    break
                except (PermissionError, OSError) as e:
                    err_str = str(e)
                    if _is_lock_error(err_str):
                        # : 50ms, 100ms, 150ms, 200ms, 250ms...
                        time.sleep(0.05 + 0.05 * attempt)
                        continue
                    raise
            if not replaced:
                # ===== FIX 4: fallback — rename =====
                # os.replace 8 .
                try:
                    with open(self.path, 'wb') as f:
                        # (header + candles)
                        with open(temp, 'rb') as src:
                            f.write(src.read())
                    replaced = True
                except Exception as fallback_err:
                    if not _is_lock_error(str(fallback_err)):
                        logmsg(f"[write:{self.symbol}] fallback write failed: {fallback_err}")
            try:
                if os.path.exists(temp): os.remove(temp)
            except Exception: pass
            if replaced:
                self.last_write = time.time()
                if self.candles:
                    self.last_saved_close = self.candles[-1]['close']
                    self.last_saved_candle_time = self.candles[-1]['time']
                    self.last_saved_candle_count = len(self.candles)
                self.dirty = False
                return True
            return False
        except Exception as e:
            err_str = str(e).lower()
            # ===== FIX 8: WinError 2 (file not found) + WinError 5 + 32 =====
            # — retry .
            if not any(x in err_str for x in [
                'winerror 2', 'winerror 5', 'winerror 32', 'winerror 13',
                'introuvable', 'refusé', 'access', 'permission', 'used by another',
                'ebusy', 'eperm', 'no such file'
            ]):
                logmsg(f"[write:{self.symbol}] write failed: {e}")
            try:
                if os.path.exists(temp): os.remove(temp)
            except Exception: pass
            return False

class WriterThread(threading.Thread):
    """FIX 11: WriterThread — HST 500ms Asset.write.
 
 : (1000 4s).
 :
 - fetch_candles_with_retry (1000 )
 - Asset.write HST {derived_symbol}{PERIOD}.hst (AUDJPY-OTC1.hst)
 - WriterThread asset.dirty 100ms + HST 500ms
 
 FIX 10 ( ) realtime_stream MT4_WRITER.update_candle.
 Asset.write WriterThread MT4_WRITER
 .
 """
    def __init__(self):
        super().__init__(daemon=True, name="WriterThread")
        self.running = True
    def run(self):
        while self.running:
            try:
                now = time.time()
                dirty_count = 0
                for asset in ALL_STREAMING_ASSETS:
                    # ===== FIX 11: MT4_WRITER =====
                    # ( — )
                    if asset.symbol in MT4_WRITER.sync_state:
                        # Still update web store even for MT4_WRITER-managed assets
                        try:
                            _web_update_asset(asset, full_resync=True)
                        except Exception:
                            pass
                        continue
                    if asset.dirty and (now - asset.last_write >= WRITE_INTERVAL):
                        if asset.write():
                            dirty_count += 1
                            # Update web dashboard candle store
                            try:
                                _web_update_asset(asset, full_resync=True)
                            except Exception:
                                pass
                if dirty_count > 0: refresh_mt4()
                time.sleep(0.1)
            except Exception as e:
                logmsg(f"[WriterThread] loop error: {e}")
                time.sleep(0.5)

writer_thread = WriterThread()
writer_thread.start()

async def connect_quotex(email, password, force_fresh=False, max_attempts=3):
    global CLIENT, CONNECTION_ALIVE, EMAIL, PASSWORD
    EMAIL, PASSWORD = email, password
    for attempt in range(1, max_attempts + 1):
        try:
            if CLIENT:
                try:
                    close_task = asyncio.create_task(CLIENT.close())
                    await asyncio.wait([close_task], timeout=3.0)
                except Exception: pass
                finally: CLIENT = None
            await asyncio.sleep(0.3)
            if force_fresh or attempt > 1:
                session_manager.delete_session_file()
                session_manager.delete_browser_dir()
            # FIX K: QX_HOST ( )
            CLIENT = Quotex(email=email, password=password, host=QX_HOST, lang="en")
            with suppress_terminal_output():
                check, reason = await CLIENT.connect()
            if check:
                try:
                    await CLIENT.change_account("PRACTICE")
                    await asyncio.sleep(0.5)
                except Exception: pass
                try: await CLIENT.get_all_assets()
                except Exception: pass
                CONNECTION_ALIVE = True
                # FIX K:
                session_manager.record_success(email, host=QX_HOST)
                return True
            else:
                error_msg = str(reason) if reason else "Unknown error"
                session_manager.record_failure(error_msg)
        except Exception as e:
            error_msg = str(e)[:200]
            session_manager.record_failure(error_msg)
            if attempt < max_attempts: await asyncio.sleep(5 * attempt)
    CONNECTION_ALIVE = False
    return False

async def keepalive_loop():
    # ===== FIX 7: keepalive (5s) + =====
    # : " ".
    # : keepalive_loop
    # `await asyncio.sleep(KEEPALIVE_PING_INTERVAL)` .
    # : `asyncio.sleep` (0.5s) .
    # keepalive .
    tick_count = 0
    last_ping_at = 0.0
    while True:
        await asyncio.sleep(0.5)  # 500ms ()
        now = time.time()
        # : ping
        if now - last_ping_at < KEEPALIVE_PING_INTERVAL:
            continue
        last_ping_at = now
        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None: continue
        try:
            # 1) engine.io ping ( Socket.IO EIO=3) —
            CLIENT.api.send_websocket_request("2", no_force_send=False)
            # 2) application-level tick —
            CLIENT.api.send_websocket_request('42["tick"]', no_force_send=False)
            # 3)
            if tick_count % 3 == 0:
                CLIENT.api.send_websocket_request('42["instruments/get"]', no_force_send=False)
            tick_count += 1
        except Exception:
            pass


async def stale_message_watchdog():
    # ===== FIX: watchdog + =====
    # WS STALE_MESSAGE_TIMEOUT (45s)
    # .
    # latency ~25s <5s.
    # FIX B: auto_reconnect
    # (> ) —
    # .
    global CONNECTION_ALIVE, LAST_CONNECTION_DROP_TIME
    while True:
        await asyncio.sleep(STALE_WATCHDOG_INTERVAL)
        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            continue
        try:
            silent_for = time.time() - CLIENT.api.last_message_at
            if silent_for > STALE_MESSAGE_TIMEOUT:
                logmsg(
                    f"[stale_watchdog] no messages for {silent_for:.1f}s "
                    f"(>{STALE_MESSAGE_TIMEOUT}s); recycling connection."
                )
                # ===== FIX B: =====
                # LONG_DISCONNECT_THRESHOLD (1h)
                # .
                if LAST_CONNECTION_DROP_TIME == 0:
                    LAST_CONNECTION_DROP_TIME = time.time()
                    logmsg(f"[stale_watchdog] drop time recorded at {LAST_CONNECTION_DROP_TIME:.0f}")
                CONNECTION_ALIVE = False
                # WS close frame on_close
                try:
                    if CLIENT.api.websocket_client and CLIENT.api.websocket_client.wss:
                        CLIENT.api.websocket_client.wss.close()
                except Exception:
                    pass
                # auto_reconnect
        except Exception as e:
            logmsg(f"[stale_watchdog] error: {e}")

async def health_monitor():
    global LAST_HEALTH_CHECK, CONNECTION_ALIVE
    consecutive_dead_checks = 0
    while True:
        await asyncio.sleep(HEALTH_CHECK_INTERVAL)
        now = time.time()
        LAST_HEALTH_CHECK = now
        if not CONNECTION_ALIVE or CLIENT is None:
            consecutive_dead_checks = 0
            continue
        is_dead = False
        dead_reason = ""
        stale_count = sum(1 for a in ALL_STREAMING_ASSETS if a.updates > 0 and (now - a.last_update_time) > STALE_DATA_TIMEOUT)
        if stale_count > len(ALL_STREAMING_ASSETS) * STALE_RATIO_TRIGGER:
            is_dead = True
            dead_reason = f"stale ratio {stale_count}/{len(ALL_STREAMING_ASSETS)} exceeded {STALE_RATIO_TRIGGER}"
        if is_dead:
            logmsg(f"[health_monitor] marking connection DEAD: {dead_reason}")
            CONNECTION_ALIVE = False
            consecutive_dead_checks = 0

async def auto_reconnect():
    # ===== FIX B: + =====
    # : " ".
    # ( stale_message_watchdog )
    # LONG_DISCONNECT_THRESHOLD (1h).
    # 1000 .
    # FIX K: QX_HOST
    global CLIENT, CONNECTION_ALIVE, RECONNECTING, LAST_CONNECTION_DROP_TIME, QX_HOST
    consecutive_failures = 0
    while True:
        await asyncio.sleep(RECONNECT_CHECK_INTERVAL)
        # ===== FIX B: ( ) =====
        # stale_message_watchdog
        # (on_close on_error connect_quotex ).
        # .
        if not CONNECTION_ALIVE and LAST_CONNECTION_DROP_TIME == 0:
            LAST_CONNECTION_DROP_TIME = time.time()
            logmsg(f"[reconnect] connection loss detected at {LAST_CONNECTION_DROP_TIME:.0f}; "
                   f"will re-fetch all candles if outage exceeds {LONG_DISCONNECT_THRESHOLD}s")
        if CONNECTION_ALIVE or RECONNECTING:
            consecutive_failures = 0
            continue
        RECONNECTING = True
        try:
            email = session_manager.get_saved_email()
            # ===== FIX: try RECONNECTING =====
            # : `if not (email and PASSWORD): continue`
            # => try RECONNECTING = True =>
            # => !
            if not (email and PASSWORD):
                # RECONNECTING
                RECONNECTING = False
                continue
            delay = 0 if consecutive_failures == 0 else min(RECONNECT_BASE_DELAY * (2 ** (consecutive_failures - 1)), RECONNECT_MAX_DELAY)
            if delay > 0:
                logmsg(f"[reconnect] connection lost, retrying in {delay:.0f}s...")
                await asyncio.sleep(delay)
            else:
                logmsg("[reconnect] connection lost, reconnecting immediately...")
            # FIX K:
            _saved_host = session_manager.get_saved_host()
            if _saved_host and QX_HOST != _saved_host:
                QX_HOST = _saved_host
                logmsg(f"[reconnect] using saved host: {QX_HOST}")
            success = await connect_quotex(email, PASSWORD, force_fresh=True, max_attempts=1)
            if success:
                logmsg("[reconnect] reconnect successful, restarting streams...")
                consecutive_failures = 0
                # ===== FIX 7: auto-throttle ( ) =====
                # ===== FIX: last_message_at =====
                # stale_watchdog .
                if CLIENT is not None and CLIENT.api is not None:
                    CLIENT.api.last_message_at = time.time()
                # ===== FIX B: =====
                drop_duration = 0.0
                should_refetch_all = False
                if LAST_CONNECTION_DROP_TIME > 0:
                    drop_duration = time.time() - LAST_CONNECTION_DROP_TIME
                    if drop_duration > LONG_DISCONNECT_THRESHOLD:
                        should_refetch_all = True
                        logmsg(
                            f"[reconnect] LONG disconnect detected: {drop_duration/60:.1f} min "
                            f"> {LONG_DISCONNECT_THRESHOLD/60:.0f} min threshold — "
                            f"will re-fetch ALL candles from scratch"
                        )

                LAST_CONNECTION_DROP_TIME = 0
                if should_refetch_all:
                    # streams
                    try:
                        asyncio.run_coroutine_threadsafe(refetch_all_candles(), ASYNC_LOOP)
                    except Exception as e:
                        logmsg(f"[reconnect] failed to schedule full re-fetch: {e}")
                        # fallback: streams
                        for asset in ALL_STREAMING_ASSETS:
                            try:
                                if asset.stream_task and not asset.stream_task.done():
                                    asset.stream_task.cancel()
                                asset.streaming = False
                                asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
                                await asyncio.sleep(0.05)
                            except Exception as e2:
                                logmsg(f"[reconnect] failed to restart stream for {asset.symbol}: {e2}")
                else:
                    # (< ) — streams
                    if drop_duration > 0:
                        logmsg(f"[reconnect] short disconnect ({drop_duration:.1f}s) — restarting streams only")
                    for asset in ALL_STREAMING_ASSETS:
                        try:
                            if asset.stream_task and not asset.stream_task.done():
                                asset.stream_task.cancel()
                            asset.streaming = False
                            asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
                            await asyncio.sleep(0.05)
                        except Exception as e:
                            logmsg(f"[reconnect] failed to restart stream for {asset.symbol}: {e}")
            else:
                consecutive_failures += 1
        except Exception as e:
            logmsg(f"[reconnect] unexpected error: {e}")
            consecutive_failures += 1
        finally:
            RECONNECTING = False

def _make_progress_printer(symbol: str, start_ts: float, idx: int, total: int):
    display = pretty_asset_name(symbol)
    def on_progress(current, total, label=None, worker_label=None):
        total = total or FETCH_DURATION_SECONDS
        pct = min(current / total, 1.0) if total > 0 else 0
        bar_len = 20
        filled = int(bar_len * pct)
        bar = "#" * filled + "-" * (bar_len - filled)
        elapsed = time.time() - start_ts
        print(f"\r  {display:<25} [{bar}] {pct*100:4.1f}% {elapsed:>2.0f}s", end="", flush=True)
    return on_progress

async def fetch_candles_once(asset: Asset, idx=1, total=1):
    api_name = asset.api_symbol
    display_name = asset.symbol
    candles = []
    # Sub-minute timeframes: fetch period=1 (1s candles) then aggregate locally
    is_sub_minute = PERIOD_SECONDS < 60
    fetch_period = 1 if is_sub_minute else PERIOD_SECONDS
    if is_sub_minute:
        # Use get_candles (single request) — more reliable for period=1
        # Make staggered requests going backwards in time
        try:
            on_progress = _make_progress_printer(display_name, time.time(), idx, total)
            try: on_progress(FETCH_DURATION_SECONDS, FETCH_DURATION_SECONDS)
            except Exception: pass
            # الهدف: نحاول جلب ما يكفي لـ INITIAL_CANDLES شموع مجمّعة
            # INITIAL_CANDLES * PERIOD_SECONDS = عدد شموع 1s المطلوبة
            # هامش 1.5x (بدل 2x) لتقليل وقت الجلب وبالتالي تقليل الفجوة الزمنية
            # الفجوة الكبيرة = شموع مفقودة أكثر بين التاريخي والبث المباشر
            target_1s_count = int(INITIAL_CANDLES * PERIOD_SECONDS * 1.5)
            chunk_seconds = 500  # ~500 1s candles per request (server limit)
            all_candles_1s = []
            current_end = time.time()
            # زيادة max_chunks من 20 → 40 لضمان جلب كافٍ حتى للأصول البطيئة
            max_chunks = 40
            chunks_done = 0
            # تتبع الـ chunks الفارغة المتتالية (للإيقاف المبكر الذكي)
            empty_chunks_in_a_row = 0
            while len(all_candles_1s) < target_1s_count and chunks_done < max_chunks:
                chunk_end = current_end - (chunks_done * chunk_seconds)
                try:
                    res_chunk = await asyncio.wait_for(
                        CLIENT.get_candles(api_name, chunk_end, chunk_seconds, fetch_period),
                        timeout=20,
                    )
                except Exception as e:
                    if chunks_done == 0:
                        logmsg(f"[fetch:{display_name}] get_candles(period=1) chunk {chunks_done+1} failed: {e}")
                    # retry once on transient error
                    if empty_chunks_in_a_row < 2:
                        empty_chunks_in_a_row += 1
                        await asyncio.sleep(0.2)
                        continue
                    break
                if not res_chunk or len(res_chunk) == 0:
                    empty_chunks_in_a_row += 1
                    # 3 chunks فارغة متتالية = نهاية التاريخ المتاح → توقف
                    if empty_chunks_in_a_row >= 3:
                        break
                    chunks_done += 1
                    continue
                # عتبة إيقاف أقل صرامة (من 50 → 10): بعض الأصول تُرجع 20-30 شمعة فقط في نهاية الأسبوع
                # هذا طبيعي ولا يعني أننا وصلنا لنهاية التاريخ
                if len(res_chunk) < 10 and chunks_done > 0:
                    all_candles_1s.extend(res_chunk)
                    break
                empty_chunks_in_a_row = 0
                all_candles_1s.extend(res_chunk)
                chunks_done += 1
                try:
                    pct = min(len(all_candles_1s) / target_1s_count, 1.0)
                    on_progress(pct * FETCH_DURATION_SECONDS, FETCH_DURATION_SECONDS)
                except Exception:
                    pass
                # delay صغير (0.03 بدل 0.05) لتسريع الجلب
                await asyncio.sleep(0.03)
            # De-duplicate by time
            seen_ts = set()
            unique_1s = []
            for c in all_candles_1s:
                if isinstance(c, dict):
                    ts = int(float(c.get('time', c.get('timestamp', 0))))
                    if ts not in seen_ts:
                        seen_ts.add(ts)
                        unique_1s.append(c)
            candles = unique_1s
            # No log message here — fetch_candles_with_retry prints the final count
        except Exception as e:
            print()
            logmsg(f"[fetch:{display_name}] get_candles(period=1) failed: {e}")
    else:
        # 60s+ timeframe — use parallel get_historical_candles
        if hasattr(CLIENT, 'get_historical_candles'):
            try:
                on_progress = _make_progress_printer(display_name, time.time(), idx, total)
                res = await asyncio.wait_for(
                    CLIENT.get_historical_candles(
                        api_name,
                        amount_of_seconds=FETCH_DURATION_SECONDS,
                        period=PERIOD_SECONDS,
                        max_workers=FETCH_MAX_WORKERS,
                        progress_callback=on_progress
                    ),
                    timeout=60,
                )
                if res and len(res) > 0: candles = res
            except Exception as e:
                print()
                logmsg(f"[fetch:{display_name}] get_historical_candles failed: {e}")
    if candles:
        formatted = []
        for c in candles:
            if not isinstance(c, dict): continue
            try:
                ts = int(float(c.get("time", c.get("timestamp", 0))))
                # Align to fetch_period (1s for sub-minute, PERIOD_SECONDS otherwise)
                aligned = _align_time(ts, period_seconds=fetch_period)
                o, h, l, cl = float(c.get("open", 0)), float(c.get("high", c.get("max", 0))), float(c.get("low", c.get("min", 0))), float(c.get("close", 0))
                if o > 0 and h > 0 and l > 0 and cl > 0:
                    formatted.append({'time': aligned, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': random.randint(50, 200)})
            except Exception: continue
        # Aggregate 1s candles into target subsecond timeframe
        if is_sub_minute and formatted:
            formatted = _aggregate_sub_minute(formatted, PERIOD_SECONDS)
        seen, unique = set(), []
        for c in formatted:
            if c['time'] not in seen:
                seen.add(c['time'])
                unique.append(c)
        unique.sort(key=lambda x: x['time'])
        return unique[-INITIAL_CANDLES:]
    return []


# ==============================================================================
# ===== BRIDGE FETCH HELPER (سد فجوة الشموع الأخيرة بين التاريخي والبث) =====
# ==============================================================================
# هذه الدالة المستقلة تُحاكي أسلوب كود 199 الشموع الذي يعمل بدون ثغرات:
#   1) طلب واحد (وليس متوازي) عبر CLIENT.get_candles
#   2) ينتهي عند time.time() الحالي (وليس T0 عند بداية الجلب التاريخي)
#   3) يستقبل آخر BRIDGE_FETCH_CANDLES شموع بما فيها الشمعة الحالية المتشكلة
#   4) يدمجها مع الشموع التاريخية (الشمعة الجسرية تستبدل التاريخية في نفس الفترة)
#
# الأمان:
#   - إذا فشلت لأي سبب، تُرجع existing_candles كما هي دون أي تغيير
#   - لا تُكسر أبداً سير عمل fetch_candles_with_retry
#   - تُحترم BRIDGE_FETCH_ENABLED=False (يمكن تعطيلها فوراً)
#   - تستخدم Semaphore لمنع إرهاق الخادم بطلبات متزامنة
# ==============================================================================
async def _bridge_fetch_recent_candles(asset: Asset, existing_candles: list) -> list:
    """جلب جسري لآخر BRIDGE_FETCH_CANDLES شمعة لسد فجوة 4-5 شموع.

    Args:
        asset: كائن Asset
        existing_candles: قائمة الشموع التاريخية المُجلبَة مسبقاً

    Returns:
        قائمة مدمجة (تاريخي + جسري) مرتبة ومُزالة التكرار، أو existing_candles
        كما هي عند فشل الجلب (الأمان: لا تُكسر العملية أبداً).
    """
    # ── فحوصات الأمان الأولية ─────────────────────────────────────────────
    if not BRIDGE_FETCH_ENABLED:
        return existing_candles
    if not existing_candles or len(existing_candles) == 0:
        return existing_candles
    if CLIENT is None or CLIENT.api is None:
        return existing_candles
    if not getattr(getattr(CLIENT, 'api', None), 'state', None):
        return existing_candles
    if not getattr(CLIENT.api.state, 'check_accepted_connection', False):
        return existing_candles

    # ── إنشاء Semaphore بأمان (lazy init على الـ loop الحالي) ──────────────
    global _BRIDGE_FETCH_SEMAPHORE
    if _BRIDGE_FETCH_SEMAPHORE is None:
        try:
            _BRIDGE_FETCH_SEMAPHORE = asyncio.Semaphore(BRIDGE_FETCH_SEMAPHORE_LIMIT)
        except RuntimeError:
            # الـ loop غير جاهز — تُرجع existing_candles دون كسر العمل
            return existing_candles

    try:
        async with _BRIDGE_FETCH_SEMAPHORE:
            is_sub_minute = PERIOD_SECONDS < 60
            # ✨ السر: استخدم time.time() الحالي (وليس T0 عند بداية الجلب التاريخي)
            bridge_end_time = int(time.time())
            bridge_candles = []

            if is_sub_minute:
                # ── للثواني الفرعية: جلب 1s ثم تجميع محلياً ──────────────────
                # هامش 5x لضمان تغطية كاملة للفجوة الزمنية الكبيرة المحتملة
                # (BRIDGE_FETCH_CANDLES=15 × PERIOD_SECONDS=5 × 5 = 375 ثانية من شموع 1s)
                # هذا يضمن أن الجسر يغطي 75 شمعة 5s — أكثر من كافٍ لأي فجوة
                bridge_1s_offset = BRIDGE_FETCH_CANDLES * PERIOD_SECONDS * 5
                try:
                    bridge_1s = await asyncio.wait_for(
                        CLIENT.get_candles(
                            asset.api_symbol,
                            bridge_end_time,
                            bridge_1s_offset,
                            1  # period=1 (1s candles — مدعوم دائماً من الخادم)
                        ),
                        timeout=BRIDGE_FETCH_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    logmsg(f"[bridge:{asset.symbol}] 1s fetch timeout (non-fatal)")
                    return existing_candles
                except Exception as e:
                    logmsg(f"[bridge:{asset.symbol}] 1s fetch failed (non-fatal): {e}")
                    return existing_candles

                if not bridge_1s:
                    return existing_candles

                # تنسيق شموع 1s
                bridge_formatted = []
                for c in bridge_1s:
                    if not isinstance(c, dict):
                        continue
                    try:
                        ts = int(float(c.get("time", c.get("timestamp", 0))))
                        aligned = _align_time(ts, period_seconds=1)
                        o = float(c.get("open", 0) or 0)
                        h = float(c.get("high", c.get("max", 0)) or 0)
                        l = float(c.get("low", c.get("min", 0)) or 0)
                        cl = float(c.get("close", c.get("c", 0)) or 0)
                        if o > 0 and h > 0 and l > 0 and cl > 0:
                            bridge_formatted.append({
                                'time': aligned, 'open': o, 'high': h,
                                'low': l, 'close': cl, 'volume': 1
                            })
                    except Exception:
                        continue

                # تجميع الـ 1s إلى الإطار الزمني المطلوب (5s/10s/15s/30s)
                bridge_candles = _aggregate_sub_minute(bridge_formatted, PERIOD_SECONDS)
            else:
                # ── لإطارات 60s+: استخدام _fetch_historical_batch مباشرة ──
                # لماذا؟ get_candles تُعيد subscribe للـ WebSocket مما يتعارض مع
                # realtime_stream الذي يعمل في الخلفية. _fetch_historical_batch
                # يستخدم event_name فريد (مع index) ولا يُعيد subscribe.
                # هذا يحل مشكلة "الفجوة عادت في M1+".
                bridge_offset = PERIOD_SECONDS * BRIDGE_FETCH_CANDLES
                # index فريد لتجنب التعارض مع get_historical_candles السابق
                _bridge_index = next(_request_counter)
                try:
                    bridge_raw = await asyncio.wait_for(
                        CLIENT._fetch_historical_batch(
                            asset.api_symbol,
                            bridge_end_time,
                            bridge_offset,
                            PERIOD_SECONDS,
                            _bridge_index,
                            BRIDGE_FETCH_TIMEOUT
                        ),
                        timeout=BRIDGE_FETCH_TIMEOUT + 5,  # هامش 5s إضافي
                    )
                except asyncio.TimeoutError:
                    logmsg(f"[bridge:{asset.symbol}] fetch timeout (non-fatal)")
                    return existing_candles
                except Exception as e:
                    logmsg(f"[bridge:{asset.symbol}] fetch failed (non-fatal): {e}")
                    return existing_candles

                if not bridge_raw:
                    return existing_candles

                # تحويل النتيجة عبر _parse_historical_candles (نفس آلية get_historical_candles)
                try:
                    bridge_parsed = CLIENT._parse_historical_candles(bridge_raw)
                except Exception:
                    bridge_parsed = []

                if not bridge_parsed:
                    return existing_candles

                # تنسيق شموع الجسر
                for c in bridge_parsed:
                    if not isinstance(c, dict):
                        continue
                    try:
                        ts = int(c.get("time", c.get("timestamp", 0)))
                        aligned = _align_time(ts, period_seconds=PERIOD_SECONDS)
                        o = float(c.get("open", 0) or 0)
                        h = float(c.get("high", 0) or 0)
                        l = float(c.get("low", 0) or 0)
                        cl = float(c.get("close", 0) or 0)
                        if o > 0 and h > 0 and l > 0 and cl > 0:
                            bridge_candles.append({
                                'time': aligned, 'open': o, 'high': h,
                                'low': l, 'close': cl, 'volume': 1
                            })
                    except Exception:
                        continue

            if not bridge_candles:
                return existing_candles

            # ── الدمج الآمن: الجسر يستبدل التاريخي في نفس الفترة الزمنية ───
            # (الشموع الجسرية أحدث وأدق، خاصة للشموع الأخيرة غير المكتملة)
            bridge_by_time = {c['time']: c for c in bridge_candles}
            merged_list = []
            for c in existing_candles:
                if c['time'] in bridge_by_time:
                    # استبدل الشمعة التاريخية بالجسرية الأحدث
                    merged_list.append(bridge_by_time.pop(c['time']))
                else:
                    merged_list.append(c)
            # أضف الشموع الجسرية المتبقية (جديدة، غير موجودة في التاريخي)
            merged_list.extend(bridge_by_time.values())

            # ── الترتيب وإزالة التكرار ─────────────────────────────────────
            seen = set()
            unique = []
            for c in sorted(merged_list, key=lambda x: x['time']):
                if c['time'] not in seen:
                    seen.add(c['time'])
                    unique.append(c)

            # قص إلى INITIAL_CANDLES (نفس سلوك الكود الأصلي)
            result = unique[-INITIAL_CANDLES:]

            # تسجيل بسيط (فقط إذا تم إضافة شموع جديدة فعلية)
            added = len(result) - len(existing_candles)
            if added > 0:
                logmsg(f"[bridge:{asset.symbol}] +{added} new candles bridged (total {len(result)})")

            return result

    except Exception as e:
        # ── الأمان النهائي: لا تُكسر الجلب التاريخي أبداً ──────────────────
        try:
            logmsg(f"[bridge:{asset.symbol}] bridge fetch error (non-fatal): {e}")
        except Exception:
            pass
        return existing_candles


async def fetch_candles_with_retry(asset: Asset, max_retries=3, idx=1, total=1):
    # For sub-minute, use lower threshold + 1 retry (server caps ~500-1000 1s candles)
    is_sub_minute = PERIOD_SECONDS < 60
    threshold = 20 if is_sub_minute else MIN_CANDLES_THRESHOLD
    max_retries = 1 if is_sub_minute else MAX_FETCH_RETRIES
    last_error = None
    for attempt in range(1, max_retries + 1):

        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            logmsg(f"[fetch_retry:{asset.symbol}] connection dead before attempt {attempt}; waiting for reconnect...")
            # (timeout 15s)
            try:
                await wait_until(
                    lambda: CONNECTION_ALIVE and CLIENT is not None and CLIENT.api is not None,
                    timeout=15.0,
                    poll_interval=0.5,
                )
            except asyncio.TimeoutError:
                logmsg(f"[fetch_retry:{asset.symbol}] reconnect did not happen within 15s; giving up on this asset")
                return 0, attempt
        try:
            candles = await fetch_candles_once(asset, idx, total)
        except Exception as e:
            candles = []
            last_error = e
            logmsg(f"[fetch_retry:{asset.symbol}] attempt {attempt}/{max_retries} raised: {e}")
        # ===== BRIDGE FETCH: سد فجوة 4-5 شموع بين التاريخي والبث المباشر =====
        # استدعاء آمن: أي خطأ يُرجع candles كما هي دون كسر العملية.
        # يُجرّب آخر BRIDGE_FETCH_CANDLES شمعة تنتهي عند time.time() الحالي.
        if candles and len(candles) > 0:
            try:
                candles = await _bridge_fetch_recent_candles(asset, candles)
            except Exception as bridge_err:
                # الأمان التام: لا تُكسر الجلب التاريخي أبداً
                logmsg(f"[fetch_retry:{asset.symbol}] bridge skipped (non-fatal): {bridge_err}")
        if len(candles) >= threshold:
            # Merge historical candles with any live ticks collected during fetch
            # (realtime_stream may have appended live candles to asset.candles)
            live_candles = []
            if asset.candles:
                hist_times = set(c['time'] for c in candles)
                for c in asset.candles:
                    if c['time'] not in hist_times and c['time'] > (candles[-1]['time'] if candles else 0):
                        live_candles.append(c)
            asset.candles = candles + live_candles
            if asset.candles: asset.price = asset.candles[-1]['close']
            asset.write(force=True)
            # Update MT4_WRITER.sync_state with the full historical + live candles
            # so update_candle doesn't overwrite HST with only the few live candles
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
            return len(asset.candles), attempt

        # Merge even for low counts
        live_candles = []
        if asset.candles:
            hist_times = set(c['time'] for c in candles)
            for c in asset.candles:
                if c['time'] not in hist_times and c['time'] > (candles[-1]['time'] if candles else 0):
                    live_candles.append(c)
        asset.candles = candles + live_candles
        if asset.candles: asset.price = asset.candles[-1]['close']
        asset.write(force=True)
        # Update sync_state even for low counts
        if asset.candles:
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
        # ===== FIX 3: exponential backoff retries =====
        if attempt < max_retries:
            delay = min(RETRY_BACKOFF_BASE * (2 ** (attempt - 1)), RETRY_BACKOFF_MAX)
            logmsg(f"[fetch_retry:{asset.symbol}] attempt {attempt}/{max_retries} got {len(candles)} candles; retry in {delay:.1f}s")
            await asyncio.sleep(delay)
    if last_error:
        logmsg(f"[fetch_retry:{asset.symbol}] all {max_retries} attempts failed. Last error: {last_error}")
    return len(candles), max_retries


# ==============================================================================
# SUBSECOND STREAM — separate system for 5s/10s/15s/30s timeframes
# Does NOT use fetch_candles_with_retry, MT4_WRITER.update_candle, or mt4_gap_filler.
# Aggregates realtime ticks into subsecond candles and writes HST directly.
# ==============================================================================

def _subsecond_align(ts: int) -> int:
    """Align timestamp to subsecond window boundary (with TZ offset for consistency)."""
    tz = _get_tz_offset()
    return ((int(ts) + tz) // SUBSECOND_SECONDS) * SUBSECOND_SECONDS

def _subsecond_write_hst(asset_symbol: str, candles: list):
    """Write subsecond HST file. Period field = 1 (MT4 minimum).
    Filename: {asset_symbol}1.hst (e.g., AUDUSD-5S-OTC1.hst)
    """
    if not candles:
        return
    file_name = f"{asset_symbol}1.hst"
    file_path = os.path.join(MT4_HISTORY_PATH, file_name)
    temp_path = file_path + '.tmp'
    try:
        os.makedirs(MT4_HISTORY_PATH, exist_ok=True)
    except Exception:
        pass
    try:
        header = bytearray(148)
        struct.pack_into('<I', header, 0, 400)
        struct.pack_into('64s', header, 4, b'MetaQuotes Software Corp.'.ljust(64, b'\x00'))
        struct.pack_into('12s', header, 68, asset_symbol[:12].encode('ascii').ljust(12, b'\x00'))
        struct.pack_into('<I', header, 80, 1)  # period = 1 (M1, MT4 minimum)
        first_price = candles[0]['close'] if candles else 0.0
        digits = _resolve_digits(asset_symbol, first_price)
        struct.pack_into('<I', header, 84, digits)
        struct.pack_into('<I', header, 88, 0)
        struct.pack_into('<I', header, 92, 0)
        body_size = len(candles) * 44
        buffer = bytearray(148 + body_size)
        buffer[:148] = header
        offset = 148
        for c in candles:
            struct.pack_into('<I', buffer, offset, int(c['time']))
            struct.pack_into('<d', buffer, offset + 4, float(c['open']))
            struct.pack_into('<d', buffer, offset + 12, float(c['low']))
            struct.pack_into('<d', buffer, offset + 20, float(c['high']))
            struct.pack_into('<d', buffer, offset + 28, float(c['close']))
            struct.pack_into('<Q', buffer, offset + 36, int(c.get('volume', 0)))
            offset += 44
        with open(temp_path, 'wb') as f:
            f.write(buffer)
        # atomic replace with retry
        replaced = False
        for attempt in range(5):
            try:
                os.replace(temp_path, file_path)
                replaced = True
                break
            except (PermissionError, OSError):
                time.sleep(0.05)
                continue
        if not replaced:
            try:
                with open(file_path, 'wb') as f:
                    f.write(buffer)
            except Exception:
                pass
    except Exception:
        pass
    finally:
        if os.path.exists(temp_path):
            try: os.remove(temp_path)
            except Exception: pass

async def fetch_subsecond_history(
    asset: Asset,
    idx: int = 1,
    total: int = 1,
    subsecond_seconds: int = None,
    target_candles: int = None,
    label: str = None,
):
    """Fetch historical subsecond candles by fetching 1s candles and aggregating.

    Strategy (per Quotex server limitations):
    1. Use `get_candles` (single request, NOT parallel get_historical_candles)
       with period=1 -- server returns ~500 1s candles per request
    2. Make multiple staggered requests going backwards in time
    3. Stop when server returns 3 empty chunks in a row (hit history limit)
    4. Aggregate 1s candles locally into 5s/10s/15s/30s

    v8.4: added optional parameters subsecond_seconds/target_candles/label.
    They fall back to SUBSECOND_SECONDS / SUBSECOND_HISTORY_CANDLES / SUBSECOND_LABEL
    when None. This lets M1 mode call us with subsecond_seconds=5 even when
    IS_SUBSECOND is False.

    Uses a semaphore (3 concurrent) to avoid overwhelming server.
    """
    if CLIENT is None or not hasattr(CLIENT, 'get_candles'):
        logmsg(f"[subfetch:{asset.symbol}] CLIENT not ready")
        return []
    api_name = asset.api_symbol
    display_name = asset.symbol
    # v8.4: resolve optional parameters -- fall back to globals if not provided
    _sec = subsecond_seconds if subsecond_seconds is not None else SUBSECOND_SECONDS
    _target = target_candles if target_candles is not None else SUBSECOND_HISTORY_CANDLES
    _label = label if label is not None else (SUBSECOND_LABEL or f"{_sec}S")
    if _sec is None or _sec <= 0:
        logmsg(f"[subfetch:{display_name}] invalid subsecond_seconds={_sec}")
        return []
    # Target: target_candles aggregated candles
    # = target_candles * subsecond_seconds 1s candles (with SUBSECOND_FETCH_MARGIN margin)
    # v8.3: use SUBSECOND_FETCH_MARGIN (1.3x) -- was hardcoded 1.5x in v8.0, 2.0x in v8.1
    target_1s_count = int(_target * _sec * SUBSECOND_FETCH_MARGIN)
    chunk_seconds = 500  # ~500 1s candles per request (server limit)
    all_candles_1s = []
    current_end = time.time()
    # v8.3: use SUBSECOND_MAX_CHUNKS (5) -- was 40 in v8.0, 60 in v8.1, now 5
    max_chunks = SUBSECOND_MAX_CHUNKS
    chunks_done = 0
    empty_chunks_in_a_row = 0
    # Semaphore (3 concurrent fetches, not 41) — created lazily on the running loop
    global _SUBSECOND_FETCH_SEMAPHORE
    if _SUBSECOND_FETCH_SEMAPHORE is None:
        _SUBSECOND_FETCH_SEMAPHORE = asyncio.Semaphore(3)
    async with _SUBSECOND_FETCH_SEMAPHORE:
        logmsg(f"[subfetch:{display_name}] start: get_candles(period=1), target ~{target_1s_count} 1s candles")
        try:
            while len(all_candles_1s) < target_1s_count and chunks_done < max_chunks:
                if not CLIENT or not CLIENT.api or not getattr(CLIENT.api.state, 'check_accepted_connection', False):
                    logmsg(f"[subfetch:{display_name}] connection lost during fetch")
                    break
                chunk_end = current_end - (chunks_done * chunk_seconds)
                try:
                    res_chunk = await asyncio.wait_for(
                        CLIENT.get_candles(api_name, chunk_end, chunk_seconds, 1),
                        timeout=20,
                    )
                except Exception as e:
                    if chunks_done == 0:
                        logmsg(f"[subfetch:{display_name}] get_candles(period=1) chunk {chunks_done+1} failed: {e}")
                    # retry on transient error
                    if empty_chunks_in_a_row < 2:
                        empty_chunks_in_a_row += 1
                        await asyncio.sleep(0.2)
                        continue
                    break
                if not res_chunk or len(res_chunk) == 0:
                    empty_chunks_in_a_row += 1
                    # 3 chunks فارغة متتالية = نهاية التاريخ المتاح
                    if empty_chunks_in_a_row >= 3:
                        break
                    chunks_done += 1
                    continue
                # عتبة إيقاف أقل صرامة (من 50 → 10)
                if len(res_chunk) < 10 and chunks_done > 0:
                    all_candles_1s.extend(res_chunk)
                    break
                empty_chunks_in_a_row = 0
                all_candles_1s.extend(res_chunk)
                chunks_done += 1
                # v8.3: bigger inter-chunk delay (0.03 -> 0.15s) -- the server was
                # throttling us after a few assets because we hammered it at 30 req/s.
                await asyncio.sleep(0.15)
                # v8.3/v8.6: user explicitly asked: if we already have enough 1s
                # candles to cover >=425 seconds of data (the original "85 5s
                # candles" threshold = 425 seconds), stop fetching more chunks.
                # v8.6: made TIME-BASED so the threshold scales correctly for any
                # _sec value. For 5s mode: 425s/5 = 85 (matches the original
                # SUBSECOND_EARLY_EXIT_CANDLES). For 1s mode: 425s/1 = 425
                # 1s candles, which is the right scale (1 chunk yields ~700 1s
                # candles = ~12 1m candles, plenty for the M1 bridge).
                _projected = len(all_candles_1s) // max(1, _sec)
                _time_based_threshold = max(1, 425 // max(1, _sec))
                if chunks_done >= 1 and _projected >= _time_based_threshold:
                    logmsg(
                        f"[subfetch:{display_name}] early-exit: {_projected} projected {_label} candles "
                        f">= {_time_based_threshold} threshold ({425}s of data); stopping chunk requests"
                    )
                    break
        except Exception as e:
            logmsg(f"[subfetch:{display_name}] FAILED: {e}")
            return []
    # De-duplicate by time (chunks may overlap)
    seen_ts = set()
    unique_1s = []
    for c in all_candles_1s:
        if isinstance(c, dict):
            ts = int(float(c.get('time', c.get('timestamp', 0))))
            if ts not in seen_ts:
                seen_ts.add(ts)
                unique_1s.append(c)
    logmsg(f"[subfetch:{display_name}] got {len(unique_1s)} 1s candles from {chunks_done} chunks, aggregating to {_label}")
    # Format 1s candles with TZ offset
    formatted_1s = []
    for c in unique_1s:
        try:
            ts = int(float(c.get("time", c.get("timestamp", 0))))
            tz = _get_tz_offset()
            aligned = ((ts + tz) // 1) * 1  # align to 1s boundary with TZ
            o = float(c.get("open", 0) or 0)
            h = float(c.get("high", c.get("max", 0)) or 0)
            l = float(c.get("low", c.get("min", 0)) or 0)
            cl = float(c.get("close", 0) or 0)
            v = int(c.get("volume", c.get("vol", 0)) or 0)
            if o > 0 and h > 0 and l > 0 and cl > 0:
                formatted_1s.append({
                    'time': aligned, 'open': o, 'high': h, 'low': l,
                    'close': cl, 'volume': v
                })
        except Exception:
            continue
    formatted_1s.sort(key=lambda x: x['time'])
    # v8.4: aggregate into the resolved _sec (not SUBSECOND_SECONDS global) and
    # limit to the resolved _target (not SUBSECOND_HISTORY_CANDLES global).
    aggregated = _aggregate_sub_minute(formatted_1s, _sec)
    result = aggregated[-_target:]
    logmsg(f"[subfetch:{display_name}] DONE: {len(unique_1s)} 1s -> {len(result)} {_label} candles")
    # v8.1: explicit verification -- warn if below the requested 500 target
    if len(result) < SUBSECOND_HISTORY_CANDLES:
        logmsg(
            f"[subfetch:{display_name}] WARNING: only {len(result)} {SUBSECOND_LABEL} candles "
            f"(target={SUBSECOND_HISTORY_CANDLES}). Server history may be limited for this asset."
        )
    return result


async def fetch_1s_and_aggregate_to_1m(asset: Asset, idx: int = 1, total: int = 1) -> list:
    """v8.6: Fetch 1-second candles and aggregate them to 1-minute candles.

    This is used as the most granular bridge for M1 mode -- the resulting 1m candles
    fill the gap between the historical 1m fetch's last candle and the live stream's
    current candle. Because each 1m candle is built from 60 consecutive 1s candles,
    there are NO gaps in the aggregated 1m candle (assuming the server's 1s data is
    continuous, which it is for popular OTC pairs).

    Args:
        asset: the Asset to fetch 1s candles for
        idx, total: progress info for logging

    Returns:
        (candles_1m, n_1s) -- the aggregated 1m candles and the raw 1s source count
    """
    # v8.5: return (candles_1m, n_1s) tuple so the caller can print the 1s
    # source count in the console before the historical fetch begins.
    if not M1_USE_1S_BRIDGE:
        return [], 0
    _fetch_start = time.time()
    try:
        candles_1s = await asyncio.wait_for(
            fetch_subsecond_history(
                asset,
                idx=idx,
                total=total,
                subsecond_seconds=1,
                target_candles=M1_1S_BRIDGE_TARGET,
                label="1S",
            ),
            timeout=M1_BRIDGE_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s fetch timeout after {M1_BRIDGE_TIMEOUT}s")
        return [], 0
    except Exception as e:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s fetch failed: {e}")
        return [], 0
    if not candles_1s:
        logmsg(f"[1s_bridge:{asset.symbol}] 1s returned 0 candles")
        return [], 0
    # Aggregate 1s -> 1m (every 60 consecutive 1s candles = 1 1m candle).
    # This is the most granular aggregation -- if the 1s data is continuous,
    # the resulting 1m candle has NO gaps (the user's explicit request).
    candles_1m = _aggregate_sub_minute(candles_1s, 60)
    _fetch_elapsed = time.time() - _fetch_start
    # v8.5/v8.6: print a clear console line showing the 1s fetch happened --
    # the user explicitly asked "must print the loading of those candles before
    # loading 1-minute candles". Use 'print' (not logmsg) so it shows on the
    # console, not just the verbose log. This print fires BEFORE the historical
    # 1m fetch begins.
    _display = pretty_asset_name(asset.symbol)
    print(
        f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{_display:<25}{Colors.RESET} "
        f"{Colors.DIM}fetched {len(candles_1s)} 1s candles in {_fetch_elapsed:.1f}s "
        f"-> {len(candles_1m)} 1m bridge{Colors.RESET}"
    )
    logmsg(
        f"[1s_bridge:{asset.symbol}] {len(candles_1s)} 1s -> {len(candles_1m)} 1m bridge candles"
    )
    return candles_1m, len(candles_1s)


async def subsecond_stream(asset: Asset):
    """Dedicated stream for subsecond timeframes (5s/10s/15s/30s).

    - Subscribes to realtime ticks (same WS subscription as normal)
    - Polls realtime_candles[asset] for tick data
    - Aggregates ticks into subsecond candle windows
    - Writes HST directly (bypasses MT4_WRITER.sync_state entirely)
    - Keeps last SUBSECOND_MAX_CANDLES (200) candles
    - NO gap filler, NO history fetch
    """
    internal = asset.api_symbol
    try:
        try:
            await wait_until(
                lambda: not (CONNECTION_ALIVE and CLIENT is None),
                timeout=10.0,
                poll_interval=0.2,
            )
        except asyncio.TimeoutError:
            pass
        if not CONNECTION_ALIVE or CLIENT is None:
            asset.streaming = False
            return
        # Subscribe to realtime 1-second ticks (period=1, always supported)
        # We aggregate locally into subsecond windows
        await CLIENT.start_candles_stream(internal, 1)
        await asyncio.sleep(0.5)
        asset.streaming = True
        asset.candles = []
        # Write empty HST immediately so MT4 can open the chart
        _subsecond_write_hst(asset.symbol, [{'time': _subsecond_align(int(time.time())), 'open': 0, 'high': 0, 'low': 0, 'close': 0, 'volume': 0}])
        last_write = time.time()
        # Fetch historical subsecond candles in the BACKGROUND using create_task
        # (run_coroutine_threadsafe doesn't work from inside the same loop)
        display_name = pretty_asset_name(internal)
        async def _background_history_fetch():
            try:
                historical = await asyncio.wait_for(fetch_subsecond_history(asset), timeout=60)
                if historical and len(historical) > 0:
                    # Merge: keep historical candles older than any tick-collected candles
                    if asset.candles:
                        oldest_tick_time = asset.candles[0]['time']
                        historical_to_keep = [c for c in historical if c['time'] < oldest_tick_time]
                        asset.candles = historical_to_keep + asset.candles
                    else:
                        asset.candles = historical
                    asset.candles = asset.candles[-SUBSECOND_MAX_CANDLES:]
                    if asset.candles and asset.price == 0:
                        asset.price = asset.candles[-1]['close']
                    # Write HST with merged data
                    _subsecond_write_hst(asset.symbol, asset.candles)
                    logmsg(f"[substream:{internal}] {len(historical)} history candles loaded + ticks active")
                else:
                    logmsg(f"[substream:{internal}] no history (ticks only)")
            except asyncio.TimeoutError:
                logmsg(f"[substream:{internal}] history fetch timeout (ticks only)")
            except Exception as e:
                logmsg(f"[substream:{internal}] background history fetch failed: {e}")
        # Schedule on the same loop — keep a strong reference to avoid GC
        _task = asyncio.create_task(_background_history_fetch())
        # Store on asset to prevent garbage collection
        if not hasattr(asset, '_bg_tasks'):
            asset._bg_tasks = set()
        asset._bg_tasks.add(_task)
        _task.add_done_callback(asset._bg_tasks.discard)
    except Exception as e:
        logmsg(f"[substream:{internal}] failed to start: {e}")
        asset.streaming = False
        return
    consecutive_errors = 0
    while CONNECTION_ALIVE:
        try:
            if CLIENT is None or not getattr(getattr(CLIENT, 'api', None), 'state', None) or getattr(CLIENT.api.state, 'status', None) != 1:
                await asyncio.sleep(0.2)
                continue
            candle = None
            if hasattr(CLIENT, 'api') and CLIENT.api:
                candle = CLIENT.api.realtime_candles.get(internal)
            if candle:
                consecutive_errors = 0
                if isinstance(candle, list) and len(candle) >= 3:
                    ts, price = int(candle[1]), float(candle[2])
                elif isinstance(candle, dict):
                    ts = int(candle.get("time", candle.get("timestamp", time.time())))
                    price = float(candle.get("price", candle.get("close", 0)))
                else:
                    await asyncio.sleep(STREAM_POLL_INTERVAL)
                    continue
                if price > 0 and ts > 0:
                    # Align to subsecond window
                    window_start = _subsecond_align(ts)
                    if asset.candles:
                        last_candle = asset.candles[-1]
                        if window_start < last_candle['time']:
                            # stale tick — ignore
                            pass
                        elif window_start == last_candle['time']:
                            # update current candle
                            last_candle['high'] = max(last_candle['high'], price)
                            last_candle['low'] = min(last_candle['low'], price)
                            last_candle['close'] = price
                            last_candle['volume'] += 1
                        else:
                            # new window — append
                            asset.candles.append({
                                'time': window_start, 'open': price, 'high': price,
                                'low': price, 'close': price, 'volume': 1
                            })
                    else:
                        asset.candles.append({
                            'time': window_start, 'open': price, 'high': price,
                            'low': price, 'close': price, 'volume': 1
                        })
                    # keep last SUBSECOND_MAX_CANDLES
                    if len(asset.candles) > SUBSECOND_MAX_CANDLES:
                        asset.candles = asset.candles[-SUBSECOND_MAX_CANDLES:]
                    # update price display
                    if asset.price != price:
                        asset.previous_price = asset.price
                    asset.price = price
                    asset.updates += 1
                    asset.last_update_time = time.time()
                    # write HST every 0.5s
                    now = time.time()
                    if now - last_write > 0.5:
                        _subsecond_write_hst(asset.symbol, asset.candles)
                        last_write = now
            await asyncio.sleep(STREAM_POLL_INTERVAL)
        except asyncio.CancelledError:
            asset.streaming = False
            raise
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= 10:
                logmsg(f"[substream:{internal}] too many consecutive errors, stopping")
                asset.streaming = False
                return
            await asyncio.sleep(0.2)
    asset.streaming = False


async def realtime_stream(asset: Asset):
    internal = asset.api_symbol
    try:
        # ===== EVENT-DRIVEN FIX =====
        # :
        # while CONNECTION_ALIVE and CLIENT is None: await asyncio.sleep(0.5)
        # timeout 200ms .
        try:
            await wait_until(
                lambda: not (CONNECTION_ALIVE and CLIENT is None),
                timeout=10.0,
                poll_interval=0.2,
            )
        except asyncio.TimeoutError:
            pass
        if not CONNECTION_ALIVE or CLIENT is None:
            asset.streaming = False
            return
        # For sub-minute timeframes, subscribe to period=1 (1s candles, always supported)
        # _align_time then buckets ticks into PERIOD_SECONDS (5s, 10s, 15s, 30s)
        #
        # v8.10: when M1_USE_1S_BRIDGE is True (which includes both TEST MODE
        # and the full flow), FORCE stream_period=1 even though PERIOD_SECONDS
        # == 60. This subscribes to 1s ticks (NOT 1m snapshots), so the server
        # doesn't send the 199-candle initial 1m burst. The 1s ticks are
        # bucketed into 1m candles by update_candle via _align_time, updating
        # the last candle for live price every second.
        if PERIOD_SECONDS == 60 and M1_USE_1S_BRIDGE:
            stream_period = 1  # 1s ticks, aggregate to 1m locally
        else:
            stream_period = 1 if PERIOD_SECONDS < 60 else PERIOD_SECONDS
        await CLIENT.start_candles_stream(internal, stream_period)
        await asyncio.sleep(0.3)  # reduced from 1.5s to minimize gap with historical fetch
        asset.streaming = True
        # ===== FIX 12: MT4_WRITER.sync_state 1000 =====
        # : MT4_WRITER.update_candle sync_state
        # => ~19 (1KB) 1000 (44KB)
        # : asset.candles (1000 ) sync_state[derived_symbol]
        # realtime_stream update_candle
        # sync_state 1000 .
        if asset.candles and asset.symbol not in MT4_WRITER.sync_state:
            MT4_WRITER.sync_state[asset.symbol] = {
                'period': PERIOD,
                'candles': list(asset.candles),  # 1000
                'last_write': 0,
                'last_price': float(asset.candles[-1]['close']) if asset.candles else 0.0,
            }
    except Exception as e:
        logmsg(f"[stream:{internal}] failed to start stream: {e}")
        asset.streaming = False
        return
    consecutive_errors = 0
    while CONNECTION_ALIVE:
        try:
            if CLIENT is None or not getattr(getattr(CLIENT, 'api', None), 'state', None) or getattr(CLIENT.api.state, 'status', None) != 1:
                # ===== EVENT-DRIVEN FIX =====
                # await asyncio.sleep(1) — polling (200ms)
                await asyncio.sleep(0.2)
                continue
            candle = None
            if not candle and hasattr(CLIENT, 'api') and CLIENT.api:
                candle = CLIENT.api.realtime_candles.get(internal)
            if candle:
                consecutive_errors = 0
                if isinstance(candle, list) and len(candle) >= 3:
                    ts, price = int(candle[1]), float(candle[2])
                elif isinstance(candle, dict):
                    ts = int(candle.get("time", candle.get("timestamp", time.time())))
                    price = float(candle.get("price", candle.get("close", 0)))
                else:
                    await asyncio.sleep(STREAM_POLL_INTERVAL)
                    continue
                if price > 0 and ts > 0:
                    # ===== FIX 10: MT4_WRITER.update_candle asset.mark_dirty =====
                    # HST MT4Writer.write_to_file ( )
                    # MT4_WRITER.update_candle sync_state[derived_symbol] + HST 200ms
                    try:
                        MT4_WRITER.update_candle(asset.symbol, PERIOD, {'time': ts, 'price': price})
                    except Exception:
                        pass
                    # asset.candles ( )
                    # FIX L5: _align_time ( tz_offset) asset.candles
                    # sync_state HST. (ts // 60 * 60)
                    # tz_offset => 1+ HST.
                    aligned_time = _align_time(ts)
                    # FIX STALE-CANDLE v2: same logic as update_candle
                    _is_new_candle = False
                    if asset.candles:
                        last_candle = asset.candles[-1]
                        if aligned_time < last_candle['time']:
                            pass  # tick for closed minute - ignore
                        elif last_candle['time'] == aligned_time:
                            last_candle['high'] = max(last_candle['high'], price)
                            last_candle['low'] = min(last_candle['low'], price)
                            last_candle['close'] = price
                        else:
                            # new candle - fill gap with flat candles first
                            _is_new_candle = True
                            period_secs = PERIOD_SECONDS if PERIOD_SECONDS > 0 else 60
                            gap = (aligned_time - last_candle['time']) // period_secs
                            if gap > 1:
                                last_close = last_candle['close']
                                fill_time = last_candle['time'] + period_secs
                                while fill_time < aligned_time:
                                    asset.candles.append({
                                        'time': fill_time,
                                        'open': last_close, 'high': last_close,
                                        'low': last_close, 'close': last_close, 'volume': 0,
                                    })
                                    fill_time += period_secs
                            asset.candles.append({'time': aligned_time, 'open': price, 'high': price, 'low': price, 'close': price, 'volume': 1})
                    else:
                        _is_new_candle = True
                        asset.candles.append({'time': aligned_time, 'open': price, 'high': price, 'low': price, 'close': price, 'volume': 1})
                    if len(asset.candles) > INITIAL_CANDLES: asset.candles = asset.candles[-INITIAL_CANDLES:]
                    # FIX G: ( )
                    if asset.price != price:
                        asset.previous_price = asset.price
                    asset.price = price
                    asset.updates += 1
                    asset.last_update_time = time.time()
                    # v9.0: Update web dashboard on every live tick.
                    # - Default path (full_resync=False): O(1) tick cache update.
                    #   This is what the chart polls at 50ms — extremely fast.
                    # - On new candle close (full_resync=True): refreshes the full
                    #   candle list so the chart sees the new bar.
                    try:
                        _web_update_asset(asset, full_resync=_is_new_candle)
                    except Exception:
                        pass
                    # asset.mark_dirty() — MT4_WRITER.update_candle
            await asyncio.sleep(STREAM_POLL_INTERVAL)
        except asyncio.CancelledError:
            asset.streaming = False
            raise
        except asyncio.TimeoutError: continue
        except Exception as e:
            consecutive_errors += 1
            if consecutive_errors >= 10:
                logmsg(f"[stream:{internal}] too many consecutive errors, stopping stream")
                asset.streaming = False
                return
            # ===== EVENT-DRIVEN FIX =====
            # await asyncio.sleep(1) — polling (200ms)
            await asyncio.sleep(0.2)
    asset.streaming = False


# ===== FIX B: (> ) =====
# : " ".
# auto_reconnect
# LONG_DISCONNECT_THRESHOLD. 1000
# HST streams —
# .
async def refetch_all_candles():
    """ .

 :
 1. streams caches 
 2. sync_state MT4_WRITER ( HST)
 3. fetch_candles_with_retry ( 1000 )
 4. realtime_stream 
 5. mt4_gap_filler 
 """
    if not ALL_STREAMING_ASSETS:
        logmsg("[refetch_all] no assets to re-fetch")
        return
    print(f"\n{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  FULL RE-FETCH: long disconnect detected — refreshing all candles{Colors.RESET}")
    print(f"  • Assets: {len(ALL_STREAMING_ASSETS)}")
    print(f"  • Target per asset: {INITIAL_CANDLES} candles")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
    # 1) streams
    for asset in ALL_STREAMING_ASSETS:
        try:
            if asset.stream_task and not asset.stream_task.done():
                asset.stream_task.cancel()
        except Exception:
            pass
        asset.streaming = False
        asset.stream_task = None
        asset.candles = []
        asset.last_saved_close = 0.0
        asset.last_saved_candle_time = 0
        asset.last_saved_candle_count = 0
        asset.dirty = True
        asset._gap_filled = False
        asset.updates = 0
        asset.last_update_time = 0
        # sync_state MT4_WRITER
        if asset.symbol in MT4_WRITER.sync_state:
            try: del MT4_WRITER.sync_state[asset.symbol]
            except Exception: pass
        if asset.symbol in MT4_WRITER._gap_filled:
            MT4_WRITER._gap_filled[asset.symbol] = False
        # Clear the SQLite-side gap_state flag too so fill_gap_once will run
        # again for this asset after the full re-fetch.
        try:
            MT4_WRITER.candle_store.clear_symbol(asset.symbol)
        except Exception:
            pass
    # 2)
    total_loaded = 0
    total_assets = len(ALL_STREAMING_ASSETS)
    consecutive_disconnects = 0
    for idx, asset in enumerate(ALL_STREAMING_ASSETS, 1):

        if not CONNECTION_ALIVE or CLIENT is None or CLIENT.api is None:
            logmsg(f"[refetch_all] connection lost again at asset {idx}/{total_assets}; aborting re-fetch")
            break
        display = pretty_asset_name(asset.api_symbol)
        start_time = time.time()
        if IS_SUBSECOND:
            # Subsecond mode: no history to re-fetch, just restart stream
            print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.CYAN}subsecond — no history to refetch{Colors.RESET}")
        else:
            try:
                candles_count, attempts = await fetch_candles_with_retry(
                    asset, max_retries=MAX_FETCH_RETRIES, idx=idx, total=total_assets
                )
                elapsed = time.time() - start_time
                if candles_count >= MIN_CANDLES_THRESHOLD:
                    total_loaded += candles_count
                    consecutive_disconnects = 0
                    attempts_str = "" if attempts == 1 else f" ({attempts} attempts)"
                    print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.GREEN}{candles_count} candles in {elapsed:.1f}s{attempts_str}{Colors.RESET}")
                else:
                    print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Only {candles_count} candles{Colors.RESET}")
            except Exception as e:
                print(f"\r{Colors.CLEAR_LINE}  {Colors.CYAN}{display:<25}{Colors.RESET} {Colors.RED}Error: {str(e)[:30]}{Colors.RESET}")
                if "Connection" in str(e) or "closed" in str(e).lower():
                    consecutive_disconnects += 1
                    if consecutive_disconnects >= MAX_RECONNECTS_DURING_FETCH:
                        logmsg(f"[refetch_all] too many disconnects ({consecutive_disconnects}); aborting")
                        break
        # 3) restart stream
        try:
            asset.stream_task = asyncio.run_coroutine_threadsafe(subsecond_stream(asset) if IS_SUBSECOND else realtime_stream(asset), ASYNC_LOOP)
        except Exception as e:
            logmsg(f"[refetch_all] failed to restart stream for {asset.symbol}: {e}")
        await asyncio.sleep(FETCH_ASSET_DELAY)
    # 4)
    if CONNECTION_ALIVE and CLIENT is not None and CLIENT.api is not None:
        try:
            asyncio.run_coroutine_threadsafe(mt4_gap_filler(), ASYNC_LOOP)
        except Exception as e:
            logmsg(f"[refetch_all] failed to schedule gap filler: {e}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  Full re-fetch complete: {total_loaded} candles across {total_assets} assets{Colors.RESET}")
    print(f"{Colors.CYAN}{'═'*60}{Colors.RESET}\n")

# ==============================================================================
# SECTION 9: MT4 SYNC ENGINE ( — )
# ==============================================================================

# ------------------------------------------------------------------------------
# CandleStore: SQLite-backed persistent candle storage.
# ------------------------------------------------------------------------------
# Why SQLite instead of JSON files:
#   - JSON is slow: full file rewrite on every save, full file load on every
#     read, no indexing. For ~1000 candles per asset across many assets this
#     wastes I/O and risks corruption if the process is killed mid-write.
#   - SQLite is transactional, atomic, indexed by (symbol, time), and
#     supports efficient range queries ("give me all candles for symbol X
#     from time A to time B") without loading the whole table into memory.
#   - Concurrent reads + a single writer are safe out of the box.
#
# Schema:
#   candles(symbol TEXT, time INTEGER, open REAL, high REAL, low REAL,
#           close REAL, volume INTEGER, PRIMARY KEY(symbol, time))
#   gap_state(symbol TEXT PRIMARY KEY, filled INTEGER, last_fill_at REAL)
#       - 'filled' is 0/1 and tracks whether fill_gap_once has already
#         succeeded for this asset. Once it is 1, MT4Writer.fill_gap_once
#         stops touching closed candles for this asset entirely.
# ------------------------------------------------------------------------------
import sqlite3 as _sqlite3
import threading as _threading

class CandleStore:
    """Thread-safe SQLite-backed candle persistence layer.

    All public methods are safe to call from any thread. A single write
    connection (guarded by a lock) serializes writes; reads use a short-lived
    read-only connection per call.
    """
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._write_lock = _threading.Lock()
        self._write_conn: Optional[_sqlite3.Connection] = None
        # Make sure parent dir exists
        try:
            parent = os.path.dirname(db_path)
            if parent:
                os.makedirs(parent, exist_ok=True)
        except Exception as e:
            pass  # silenced - non-essential diagnostic
        # Init schema on a short-lived connection
        self._init_schema()

    def _init_schema(self):
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                conn.execute("PRAGMA journal_mode=WAL;")    # crash-safe, fast writes
                conn.execute("PRAGMA synchronous=NORMAL;")  # safe + fast
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS candles (
                        symbol TEXT NOT NULL,
                        time   INTEGER NOT NULL,
                        open   REAL NOT NULL,
                        high   REAL NOT NULL,
                        low    REAL NOT NULL,
                        close  REAL NOT NULL,
                        volume INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY (symbol, time)
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_candles_symbol_time
                    ON candles(symbol, time)
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS gap_state (
                        symbol        TEXT PRIMARY KEY,
                        filled        INTEGER NOT NULL DEFAULT 0,
                        last_fill_at  REAL NOT NULL DEFAULT 0
                    )
                """)
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic

    # ------------------------------------------------------------------ writes
    def _get_write_conn(self) -> _sqlite3.Connection:
        if self._write_conn is None:
            self._write_conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            self._write_conn.execute("PRAGMA journal_mode=WAL;")
            self._write_conn.execute("PRAGMA synchronous=NORMAL;")
        return self._write_conn

    def upsert_candles(self, symbol: str, candles: list) -> int:
        """Insert-or-replace a batch of candles for the given symbol.
        Returns the number of rows written."""
        if not candles:
            return 0
        with self._write_lock:
            conn = self._get_write_conn()
            rows = 0
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for c in candles:
                    conn.execute(
                        "INSERT OR REPLACE INTO candles(symbol, time, open, high, low, close, volume) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        (symbol, int(c['time']), float(c['open']), float(c['high']),
                         float(c['low']), float(c['close']), int(c.get('volume', 0)))
                    )
                    rows += 1
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                pass  # silenced - non-essential diagnostic
                return 0
            return rows

    def append_new_candles(self, symbol: str, candles: list, after_time: int = 0) -> int:
        """Append candles whose time > after_time. Existing candles with time
        <= after_time are left untouched (frozen). Returns number of rows
        actually inserted (not the number replaced)."""
        if not candles:
            return 0
        with self._write_lock:
            conn = self._get_write_conn()
            inserted = 0
            try:
                conn.execute("BEGIN IMMEDIATE;")
                for c in candles:
                    t = int(c['time'])
                    if t <= after_time:
                        continue    # frozen - skip
                    cur = conn.execute(
                        "INSERT OR IGNORE INTO candles(symbol, time, open, high, low, close, volume) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?);",
                        (symbol, t, float(c['open']), float(c['high']),
                         float(c['low']), float(c['close']), int(c.get('volume', 0)))
                    )
                    if cur.rowcount > 0:
                        inserted += 1
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                pass  # silenced - non-essential diagnostic
                return 0
            return inserted

    def set_gap_filled(self, symbol: str, filled: bool = True, at_ts: float = None):
        if at_ts is None:
            at_ts = time.time()
        with self._write_lock:
            conn = self._get_write_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute(
                    "INSERT INTO gap_state(symbol, filled, last_fill_at) VALUES (?, ?, ?) "
                    "ON CONFLICT(symbol) DO UPDATE SET filled=excluded.filled, last_fill_at=excluded.last_fill_at;",
                    (symbol, 1 if filled else 0, float(at_ts))
                )
                conn.execute("COMMIT;")
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass

    def is_gap_filled(self, symbol: str) -> Tuple[bool, float]:
        """Returns (filled, last_fill_at)."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT filled, last_fill_at FROM gap_state WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                if row is None:
                    return (False, 0.0)
                return (bool(row[0]), float(row[1]))
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return (False, 0.0)

    # ------------------------------------------------------------------- reads
    def get_candles(self, symbol: str, limit: Optional[int] = None) -> list:
        """Return all candles for the symbol, sorted by time ascending.
        If limit is given, return only the last `limit` candles."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                if limit is None:
                    cur = conn.execute(
                        "SELECT time, open, high, low, close, volume FROM candles "
                        "WHERE symbol=? ORDER BY time ASC;",
                        (symbol,)
                    )
                else:
                    # Use a subselect to get the last N rows by time, then sort ascending.
                    cur = conn.execute(
                        "SELECT time, open, high, low, close, volume FROM candles "
                        "WHERE symbol=? ORDER BY time DESC LIMIT ?;",
                        (symbol, int(limit))
                    )
                    rows = cur.fetchall()
                    rows.reverse()
                    return [{
                        'time': r[0], 'open': r[1], 'high': r[2],
                        'low': r[3], 'close': r[4], 'volume': r[5]
                    } for r in rows]
                rows = cur.fetchall()
                return [{
                    'time': r[0], 'open': r[1], 'high': r[2],
                    'low': r[3], 'close': r[4], 'volume': r[5]
                } for r in rows]
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return []

    def get_max_time(self, symbol: str) -> int:
        """Return the largest candle timestamp stored for the symbol, or 0."""
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT MAX(time) FROM candles WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                return int(row[0]) if row and row[0] is not None else 0
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return 0

    def count(self, symbol: str) -> int:
        try:
            conn = _sqlite3.connect(self.db_path, timeout=10.0, isolation_level=None)
            try:
                cur = conn.execute(
                    "SELECT COUNT(*) FROM candles WHERE symbol=?;",
                    (symbol,)
                )
                row = cur.fetchone()
                return int(row[0]) if row else 0
            finally:
                conn.close()
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return 0

    def clear_symbol(self, symbol: str) -> int:
        """Delete all candles + gap_state for a symbol (used by full re-fetch)."""
        with self._write_lock:
            conn = self._get_write_conn()
            try:
                conn.execute("BEGIN IMMEDIATE;")
                cur = conn.execute("DELETE FROM candles WHERE symbol=?;", (symbol,))
                deleted = cur.rowcount
                conn.execute("DELETE FROM gap_state WHERE symbol=?;", (symbol,))
                conn.execute("COMMIT;")
                return deleted
            except Exception:
                try: conn.execute("ROLLBACK;")
                except Exception: pass
                return 0


# Module-level singleton (created lazily so the path can be picked once
# after APPDATA is available at runtime).
_CANDLE_STORE: Optional[CandleStore] = None
_CANDLE_STORE_LOCK = _threading.Lock()

def get_candle_store() -> CandleStore:
    """Lazy-init the global CandleStore.

    The DB lives NEXT TO THE SCRIPT / EXE (not in APPDATA) so it is easy to
    bundle with a PyInstaller exe and easy for the user to find / back up.
    - When run as a script: candles.db is created in the script's directory.
    - When frozen with PyInstaller (one-file): candles.db is created in the
      directory the exe runs from (sys.executable's parent).
    """
    global _CANDLE_STORE
    if _CANDLE_STORE is not None:
        return _CANDLE_STORE
    with _CANDLE_STORE_LOCK:
        if _CANDLE_STORE is None:
            # Resolve the directory the script / exe lives in.
            # When frozen with PyInstaller, sys.executable points to the exe
            # and we want the DB next to it (not inside the temp _MEIPASS dir).
            if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
                base_dir = os.path.dirname(os.path.abspath(sys.executable))
            else:
                base_dir = os.path.dirname(os.path.abspath(__file__))
            db_path = os.path.join(base_dir, 'candles.db')
            _CANDLE_STORE = CandleStore(db_path)
        return _CANDLE_STORE


# ==============================================================================
# SECTION 9.1: MT4 WRITER (uses CandleStore instead of JSON snapshots)
# ==============================================================================
class MT4Writer:
    """ MT4 .
 
 :
 - sync_state[asset] {period, candles, last_write, last_price}
 - seed_history: + HST 
 - update_candle: + HST 200ms
 - fill_gap_once: 20 + HST
 
 :
 - derived_symbol (AUDJPY-OTC) api_symbol 
 - PERIOD=1 (M1) 60 (H1) => AUDJPY-OTC1.hst
 - makedirs + retry + silent errors ( FIX 4/8)
 """
    def __init__(self):
        appdata = os.environ.get('APPDATA', '') or os.environ.get('HOME', '')
        self.mt4_history_path = os.path.join(appdata, 'MetaQuotes', 'Terminal', 'Common', 'Files', 'qx_hst')
        try:
            os.makedirs(self.mt4_history_path, exist_ok=True)
        except Exception as e:
            logmsg(f"Cannot create MT4 folder: {e}")
        # ===== FIX 10: sync_state derived_symbol ( AUDJPY-OTC) =====
        # seed_history + update_candle + fill_gap_once
        # => (AUDJPY-OTC1.hst)
        self.sync_state: Dict[str, Any] = {}
        self._writing_queue = set()
        self._gap_filled = {}
        # ===== FIX L8: =====
        # GAP_FILL_REFRESH_INTERVAL ( )
        # => .
        self._gap_filled_at: Dict[str, float] = {}
        # ---- PERSISTENT STORAGE: SQLite-backed candle store ----------------
        # CandleStore replaces the previous JSON snapshot approach. SQLite is
        # transactional, atomic, indexed by (symbol, time), and far faster than
        # writing/loading a 30 KB JSON file on every cycle. The DB lives at:
        #   %APPDATA%\MetaQuotes\Terminal\Common\Files\qx_hst_snapshots\candles.db
        # See SECTION 9 above for the CandleStore class definition.
        self._candle_store: Optional[CandleStore] = None   # lazy via get_candle_store()

    @property
    def candle_store(self) -> "CandleStore":
        """Lazy accessor so the DB connection is created after APPDATA is set."""
        if self._candle_store is None:
            self._candle_store = get_candle_store()
        return self._candle_store

    def load_snapshot(self, derived_symbol: str) -> Optional[list]:
        """Load candles for an asset from the SQLite store.
        Returns None if no candles exist (so seed_history falls back to the API).
        Also refreshes the in-memory gap_state from the DB."""
        try:
            stored = self.candle_store.get_candles(derived_symbol, limit=INITIAL_CANDLES)
            if not stored:
                return None
            # refresh in-memory gap_state from DB
            filled, last_at = self.candle_store.is_gap_filled(derived_symbol)
            self._gap_filled[derived_symbol] = filled
            self._gap_filled_at[derived_symbol] = last_at
            return stored
        except Exception as e:
            pass  # silenced - non-essential diagnostic
            return None

    def save_snapshot(self, derived_symbol: str, candles: list) -> None:
        """Persist the current candle list to the SQLite store.
        Called after seed_history + after each successful fill_gap_once."""
        try:
            self.candle_store.upsert_candles(derived_symbol, candles)
        except Exception as e:
            pass  # silenced - non-essential diagnostic

    def get_digits(self, symbol: str, price: float = 0.0) -> int:
        # FIX J: _resolve_digits ( mt4_digits.json)
        return _resolve_digits(symbol, price)

    def generate_hst_buffer(self, symbol: str, period: int, candles: list) -> bytes:
        # For sub-minute timeframes, write period=1 (M1) in the HST header
        # so MT4 opens it as a normal M1 file. The candles inside have actual
        # 5s/10s/15s/30s timestamps. For 60s+ timeframes, store the MT4 period int.
        header_period = 1 if PERIOD_SECONDS < 60 else period
        header = bytearray(148)
        struct.pack_into('<I', header, 0, 400)
        struct.pack_into('64s', header, 4, b'MetaQuotes Software Corp.'.ljust(64, b'\x00'))
        struct.pack_into('12s', header, 68, symbol[:12].encode('ascii').ljust(12, b'\x00'))
        struct.pack_into('<I', header, 80, header_period)
        first_price = candles[0]['close'] if candles else 0.0
        digits = self.get_digits(symbol, first_price)
        struct.pack_into('<I', header, 84, digits)
        struct.pack_into('<I', header, 88, 0)
        struct.pack_into('<I', header, 92, 0)
        body_size = len(candles) * 44
        buffer = bytearray(148 + body_size)
        buffer[:148] = header
        offset = 148
        for c in candles:
            struct.pack_into('<I', buffer, offset, int(c['time']))
            struct.pack_into('<d', buffer, offset + 4, float(c['open']))
            struct.pack_into('<d', buffer, offset + 12, float(c['low']))
            struct.pack_into('<d', buffer, offset + 20, float(c['high']))
            struct.pack_into('<d', buffer, offset + 28, float(c['close']))
            struct.pack_into('<Q', buffer, offset + 36, int(c.get('volume', 0)))
            offset += 44
        return bytes(buffer)

    def update_candle(self, asset: str, period: int, tick: dict):
        """ + HST 200ms ( ).

 Args:
 asset: derived_symbol ( "AUDJPY-OTC") — 
 period: MT4 timeframe (PERIOD=1 for M1) — 
 tick: {'time': int, 'price': float}
 """
        if asset not in self.sync_state:
            self.sync_state[asset] = {'period': period, 'candles': [], 'last_write': 0, 'last_price': 0.0}
        state = self.sync_state[asset]
        # ===== FIX L6: _align_time ( tz_offset + ) =====
        # —
        # seed_history fill_gap_once fetch_candles_once.
        aligned_time = _align_time(tick['time'])

        # FIX STALE-CANDLE v2: only the last candle (current/open) can be updated.
        # All candles before it are closed and must never be touched.
        if state['candles']:
            last_time = state['candles'][-1]['time']
            if aligned_time < last_time:
                # tick for a closed minute - ignore (protect closed candles)
                return
            elif aligned_time == last_time:
                last = state['candles'][-1]
                if tick['price'] == state['last_price']: return
                last['high'] = max(last['high'], tick['price'])
                last['low'] = min(last['low'], tick['price'])
                last['close'] = tick['price']
                last['volume'] += 1
            else:
                # new candle - check if there's a gap and fill it with flat candles
                period_secs = PERIOD_SECONDS if PERIOD_SECONDS > 0 else 60
                gap = (aligned_time - last_time) // period_secs
                if gap > 1:
                    # Fill gap with flat candles (use last close as price)
                    last_close = state['candles'][-1]['close']
                    fill_time = last_time + period_secs
                    while fill_time < aligned_time:
                        state['candles'].append({
                            'time': fill_time,
                            'open': last_close,
                            'high': last_close,
                            'low': last_close,
                            'close': last_close,
                            'volume': 0,
                        })
                        fill_time += period_secs
                # Now append the new candle (becomes the last)
                state['candles'].append({
                    'time': aligned_time, 'open': tick['price'], 'high': tick['price'],
                    'low': tick['price'], 'close': tick['price'], 'volume': 1,
                })
        else:
            state['candles'].append({
                'time': aligned_time, 'open': tick['price'], 'high': tick['price'],
                'low': tick['price'], 'close': tick['price'], 'volume': 1,
            })
        if len(state['candles']) > 1000:
            state['candles'] = state['candles'][-1000:]
        state['last_price'] = tick['price']
        now = time.time()
        if now - state['last_write'] > 0.2:
            self.write_to_file(asset, period, state['candles'])
            state['last_write'] = now

    def write_to_file(self, asset: str, period: int, candles: list):
        """ HST {asset}{period}.hst ( AUDJPY-OTC1.hst).

 Args:
 asset: derived_symbol ( "AUDJPY-OTC")
 period: MT4 timeframe (PERIOD=1 for M1)
"""
        # DISABLED: server no longer writes HST files (user request).
        # The web dashboard (Flask) is now the ONLY output — no disk writes.
        if not WRITE_HST_FILES_ENABLED:
            return
        if asset in self._writing_queue: return
        self._writing_queue.add(asset)
        file_name = f"{asset}{period}.hst"
        file_path = os.path.join(self.mt4_history_path, file_name)
        temp_path = file_path + '.tmp'
        # / +
        def _is_silent_error(err_str):
            err_str = err_str.lower()
            return any(x in err_str for x in [
                'winerror 2', 'winerror 5', 'winerror 32', 'winerror 13',
                'introuvable', 'refusé', 'acces refusé', 'access denied',
                'permission', 'used by another', 'ebusy', 'eperm',
                'no such file', 'not found', 'does not exist'
            ])
        # ( WinError 2)
        try:
            os.makedirs(self.mt4_history_path, exist_ok=True)
        except Exception:
            pass
        try:
            buffer = self.generate_hst_buffer(asset, period, candles)
            with open(temp_path, 'wb') as f:
                f.write(buffer)
            # retry WinError 5 + 32
            replaced = False
            for attempt in range(8):
                try:
                    os.replace(temp_path, file_path)
                    replaced = True
                    break
                except (PermissionError, OSError) as e:
                    if _is_silent_error(str(e)):
                        time.sleep(0.05 + 0.05 * attempt)
                        continue
                    raise
            if not replaced:
                # fallback —
                try:
                    with open(file_path, 'wb') as f:
                        f.write(buffer)
                    replaced = True
                except Exception as fallback_err:
                    if not _is_silent_error(str(fallback_err)):
                        logmsg(f"MT4 Write Error for {asset} (fallback): {fallback_err}")
        except OSError as e:
            if not _is_silent_error(str(e)):
                logmsg(f"MT4 Write Error for {asset}: {e}")
        except Exception as e:
            if not _is_silent_error(str(e)):
                logmsg(f"MT4 Write Error for {asset}: {e}")
        finally:
            self._writing_queue.discard(asset)
            if os.path.exists(temp_path):
                try: os.remove(temp_path)
                except Exception: pass

    async def seed_history(self, client, asset_obj, period: int, days: float = 0.75):
        """ + HST ( ).
 
 Args:
 client: Quotex
 asset_obj: Asset ( api_symbol symbol)
 period: MT4 timeframe (PERIOD=1 for M1) — get_candles PERIOD_SECONDS
 days: (default 0.75 = 18 )
 
 Returns:
 True False 
 """
        api_symbol = asset_obj.api_symbol
        derived_symbol = asset_obj.symbol

        # ---- SNAPSHOT FAST PATH ------------------------------------------------
        # If we have a previously-saved snapshot for this asset, use it directly.
        # This avoids re-fetching historical candles from the API on every restart
        # and prevents the "candles flicker / disappear and reappear" symptom
        # caused by the API returning slightly different candle data each call.
        # The streaming update_candle() path will simply append new candles as
        # they happen, and fill_gap_once() will only ADD new closed candles
        # (never replace existing ones, since the snapshot marks them as frozen).
        try:
            snap = self.load_snapshot(derived_symbol)
            if snap and len(snap) >= 2:
                snap = sorted(snap, key=lambda x: x['time'])[-INITIAL_CANDLES:]
                # populate sync_state from the snapshot
                self.sync_state[derived_symbol] = {
                    'period': period,
                    'candles': list(snap),
                    'last_write': 0,
                    'last_price': float(snap[-1]['close']) if snap else 0.0,
                }
                # write HST so MT4 picks them up immediately
                self.write_to_file(derived_symbol, period, snap)
                asset_obj.candles = list(snap)
                if snap:
                    asset_obj.price = snap[-1]['close']
                # gap is considered already filled (frozen) for the snapshot range
                self._gap_filled[derived_symbol] = True
                self._gap_filled_at[derived_symbol] = time.time()
                pass  # silenced - non-essential diagnostic
                return True
        except Exception as _se:
            pass  # silenced - non-essential diagnostic

        try:
            offset_seconds = int(days * 86400)
            # ===== FIX 10: get_candles PERIOD_SECONDS (60s ) =====
            # PERIOD (1 = M1 timeframe)
            candles = await client.get_candles(api_symbol, time.time(), offset_seconds, PERIOD_SECONDS)
            if candles and len(candles) > 0:
                # ===== FIX L7: _align_time ( tz_offset + ) =====
                # `t = int(c.get('time', ...)) + _tz_offset` —
                # => API 22:36:30 22:36:30
                # update_candle 22:36:00 => => .
                # : _align_time tz_offset + => .
                formatted = []
                for c in candles:
                    t = _align_time(int(c.get('time', c.get('timestamp', 0))))
                    o = float(c.get('open', c.get('o', 0)) or 0)
                    h = float(c.get('high', c.get('max', c.get('h', 0))) or 0)
                    l = float(c.get('low', c.get('min', c.get('l', 0))) or 0)
                    cl = float(c.get('close', c.get('c', 0)) or 0)
                    if o > 0 and h > 0 and l > 0 and cl > 0:
                        formatted.append({
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': 0,
                        })
                formatted.sort(key=lambda x: x['time'])
                seen = set()
                unique_candles = [c for c in formatted if not (c['time'] in seen or seen.add(c['time']))]
                # ===== FIX 10: 1000 + =====
                unique_candles = unique_candles[-INITIAL_CANDLES:]
                # ===== FIX 10: sync_state derived_symbol ( AUDJPY-OTC) =====
                self.sync_state[derived_symbol] = {
                    'period': period, 'candles': unique_candles, 'last_write': 0, 'last_price': 0.0,
                }
                # ===== FIX 10: HST derived_symbol + period (AUDJPY-OTC1.hst) =====
                self.write_to_file(derived_symbol, period, unique_candles)
                # asset_obj.candles ( )
                asset_obj.candles = unique_candles
                if unique_candles:
                    asset_obj.price = unique_candles[-1]['close']
                self._gap_filled[derived_symbol] = False
                # ---- Save the freshly-fetched candles as the snapshot so the next
                # restart uses them as-is and never re-fetches this range. ----
                self.save_snapshot(derived_symbol, unique_candles)
                return True
            return False
        except Exception as e:
            # ( spam)
            err_str = str(e).lower()
            if not any(x in err_str for x in ['winerror', 'permission', 'access', 'closed', 'connection']):
                pass  # — main fetch loop
            return False

    async def fill_gap_once(self, client, asset_obj, period: int):
        """ GAP_FILL_CANDLES + .

 (FIX L9):
 1. _align_time tz_offset + => .
 2. GAP_FILL_REFRESH_INTERVAL => .
 3. _fill_missing_slots => .
 4. 0 (volume=0) => .

 (NEW - FREEZE AFTER FIRST SUCCESS):
 5. The original fill_gap_once algorithm is left intact. The ONLY new thing
    is a persistent freeze flag in the SQLite candle store (gap_state.filled).
    Once a successful fill has run for an asset, the flag is set to 1 and
    every subsequent call to fill_gap_once returns immediately without
    touching the candles. This preserves the candles exactly as they were
    after the first fill - no flicker, no replacement of closed candles.
    A 'full re-fetch' command can clear the flag and force a new fill.

 Args:
 client: Quotex
 asset_obj: Asset ( api_symbol symbol)
 period: MT4 timeframe (PERIOD=1 for M1)
 """
        api_symbol = asset_obj.api_symbol
        derived_symbol = asset_obj.symbol

        # 0) FREEZE CHECK: if a successful fill already happened for this asset
        # (gap_state.filled == 1 in the SQLite store), do NOT touch the candles
        # at all. This is the entire fix for the 'candles flicker' symptom -
        # the original algorithm is preserved 1:1, we only skip it after the
        # first successful run.
        try:
            is_filled, _last_at = self.candle_store.is_gap_filled(derived_symbol)
            if is_filled:
                return    # frozen - keep candles exactly as they were
        except Exception:
            pass

        # 1) skip if filled recently (within GAP_FILL_REFRESH_INTERVAL)
        now_ts = time.time()
        last_fill = self._gap_filled_at.get(derived_symbol, 0)
        already_filled = self._gap_filled.get(derived_symbol, False)
        if already_filled and (now_ts - last_fill) < GAP_FILL_REFRESH_INTERVAL:
            return

        # 2) sync_state asset_obj.candles
        if derived_symbol not in self.sync_state:
            if not asset_obj.candles:
                # try to load from store first
                snap = self.load_snapshot(derived_symbol)
                if snap:
                    asset_obj.candles = snap
                else:
                    return
            self.sync_state[derived_symbol] = {
                'period': period,
                'candles': list(asset_obj.candles),
                'last_write': 0,
                'last_price': float(asset_obj.candles[-1]['close']) if asset_obj.candles else 0.0,
            }
        state = self.sync_state[derived_symbol]
        if not state['candles']:
            return

        try:
            # Fetch last GAP_FILL_CANDLES (10) recent candles to replace incomplete ones
            small_days = (GAP_FILL_CANDLES * PERIOD_SECONDS) / 86400.0
            candles = await client.get_candles(api_symbol, time.time(), int(small_days * 86400), PERIOD_SECONDS)
            if not candles:
                # Fill existing gaps even without new data
                merged = sorted(state['candles'], key=lambda x: x['time'])[-INITIAL_CANDLES:]
                merged = _fill_missing_slots(merged, PERIOD_SECONDS, max_gap=1440)
                state['candles'] = merged
                self.write_to_file(derived_symbol, period, merged)
                asset_obj.candles = merged
                self._gap_filled[derived_symbol] = True
                self._gap_filled_at[derived_symbol] = now_ts
                self.save_snapshot(derived_symbol, merged)
                # mark as permanently filled in the DB so the next cycle skips
                self.candle_store.set_gap_filled(derived_symbol, True, now_ts)
                return

            # Build candle_map: replace incomplete closed candles with real API data
            # - Current streaming candle (time >= current_period_start): SKIP (streaming handles it)
            # - Closed candles in the fetched range: REPLACE with real data (fixes small bodies)
            # - Missing candles: ADD them
            # - Synthetic candles (volume=0): REPLACE with real data
            current_period_start = _align_time(int(time.time()))
            candle_map: Dict[int, dict] = {}
            for c in state['candles']:
                candle_map[c['time']] = c
            new_count = 0
            replaced_count = 0
            for c in candles:
                t = _align_time(int(c.get('time', c.get('timestamp', 0))))
                o = float(c.get('open', c.get('o', 0)) or 0)
                h = float(c.get('high', c.get('max', c.get('h', 0))) or 0)
                l = float(c.get('low', c.get('min', c.get('l', 0))) or 0)
                cl = float(c.get('close', c.get('c', 0)) or 0)
                v = int(c.get('volume', c.get('vol', 0)) or 0)
                if o > 0 and h > 0 and l > 0 and cl > 0:
                    existing = candle_map.get(t)
                    if existing is None:
                        # genuinely missing candle (real gap) - add it
                        candle_map[t] = {
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v,
                        }
                        new_count += 1
                    elif t >= current_period_start:
                        # current streaming candle - DON'T TOUCH (streaming handles it)
                        continue
                    else:
                        # closed candle in the fetched range - REPLACE with real data
                        # (fixes small/incomplete bodies from partial streaming)
                        candle_map[t] = {
                            'time': t, 'open': o, 'high': h, 'low': l, 'close': cl, 'volume': v,
                        }
                        replaced_count += 1

            # sort + limit to INITIAL_CANDLES
            merged = sorted(candle_map.values(), key=lambda x: x['time'])[-INITIAL_CANDLES:]
            # fill remaining gaps with flat candles (max_gap=1440 = full day)
            merged = _fill_missing_slots(merged, PERIOD_SECONDS, max_gap=1440)
            state['candles'] = merged

            # write HST
            self.write_to_file(derived_symbol, period, merged)

            # update asset_obj.candles (for live price display)
            asset_obj.candles = merged
            if merged:
                asset_obj.price = merged[-1]['close']

            # 9) mark gap as filled
            self._gap_filled[derived_symbol] = True
            self._gap_filled_at[derived_symbol] = now_ts
            # 10) persist candles to the SQLite store (so the next restart
            # loads them from the DB instead of re-fetching from the API).
            self.save_snapshot(derived_symbol, merged)
            # 11) set the permanent freeze flag - subsequent fill_gap_once
            # calls for this asset will return immediately without touching
            # the candles. This is the entire fix for the 'flicker' symptom.
            self.candle_store.set_gap_filled(derived_symbol, True, now_ts)
        except Exception as e:
            err_str = str(e).lower()
            if not any(x in err_str for x in ['winerror', 'permission', 'access', 'closed', 'connection']):
                pass

MT4_WRITER = MT4Writer()

async def mt4_gap_filler():
    global GAP_FILL_SUMMARY, GAP_FILL_ACTIVE
    # Skip entirely for subsecond mode — no gap filler for 5s/10s/15s/30s
    if IS_SUBSECOND:
        GAP_FILL_SUMMARY = "GAP FILL: disabled (subsecond mode)"
        GAP_FILL_ACTIVE = False
        return
    total = len(ALL_STREAMING_ASSETS)
    GAP_FILL_SUMMARY = f"GAP FILL: waiting 60s before starting ({total} assets)..."
    await asyncio.sleep(60)
    cycle = 0
    while True:
        cycle += 1
        if not ALL_STREAMING_ASSETS:
            GAP_FILL_SUMMARY = "GAP FILL: no assets to fill"
            GAP_FILL_ACTIVE = False
            await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
            continue
        GAP_FILL_ACTIVE = True
        filled_count = 0
        skipped_count = 0
        failed_count = 0
        failed_assets = []
        t0 = time.time()
        for i, asset in enumerate(ALL_STREAMING_ASSETS, 1):
            if not CLIENT or not CLIENT.api:
                GAP_FILL_SUMMARY = f"GAP FILL: ABORTED (connection lost) | {filled_count}/{total} filled | {skipped_count} skipped"
                GAP_FILL_ACTIVE = False
                await asyncio.sleep(5)
                break
            try:
                await MT4_WRITER.fill_gap_once(CLIENT, asset, PERIOD)
                if MT4_WRITER._gap_filled.get(asset.symbol, False):
                    filled_count += 1
                else:
                    skipped_count += 1
                await asyncio.sleep(0.3)
            except Exception:
                skipped_count += 1
                failed_count += 1
                failed_assets.append(asset.symbol)
            # live progress update in banner
            GAP_FILL_SUMMARY = (
                f"GAP FILL c{cycle}: {i}/{total} done | {filled_count} filled | "
                f"{skipped_count} skipped | {failed_count} failed | {time.time()-t0:.1f}s"
            )
        else:
            # loop completed normally (no connection loss break)
            elapsed = time.time() - t0
            fail_str = f" | Failed: {', '.join(failed_assets[:5])}" if failed_assets else ""
            GAP_FILL_SUMMARY = (
                f"GAP FILL c{cycle}: COMPLETE in {elapsed:.1f}s | {filled_count}/{total} filled | "
                f"{skipped_count} skipped{fail_str} | next in {GAP_FILL_REFRESH_INTERVAL}s"
            )
            GAP_FILL_ACTIVE = False
            await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
            total = len(ALL_STREAMING_ASSETS)
            continue
        # reached here only on connection loss (break)
        GAP_FILL_ACTIVE = False
        await asyncio.sleep(GAP_FILL_REFRESH_INTERVAL)
        total = len(ALL_STREAMING_ASSETS)


WEB_PUSH_INTERVAL = 30  # seconds between full candle re-push to web dashboard

async def web_candle_refresher():
    """Every 30 seconds: re-fetch full candle history for ALL streaming assets
    and push to the web dashboard so the chart always shows fresh, complete data.
    Uses the same fetch_candles_with_retry path as the initial load.
    Skips assets if connection is down (retries next cycle).
    """
    global GAP_FILL_SUMMARY
    # Wait for initial load to complete before first push
    await asyncio.sleep(35)
    cycle = 0
    while True:
        cycle += 1
        assets = list(ALL_STREAMING_ASSETS)
        total = len(assets)
        if total == 0 or not CONNECTION_ALIVE or CLIENT is None:
            GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: waiting for connection... (next in {WEB_PUSH_INTERVAL}s)"
            await asyncio.sleep(WEB_PUSH_INTERVAL)
            continue

        pushed = 0
        skipped = 0
        t0 = time.time()
        GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: refreshing {total} assets..."

        for asset in assets:
            if not CONNECTION_ALIVE or CLIENT is None:
                GAP_FILL_SUMMARY = f"WEB PUSH c{cycle}: ABORTED (connection lost) — {pushed}/{total} pushed"
                skipped = total - pushed
                break
            try:
                candles_count, _ = await fetch_candles_with_retry(
                    asset, max_retries=3, idx=pushed+1, total=total
                )
                if candles_count > 0:
                    try:
                        _web_update_asset(asset, full_resync=True)
                    except Exception:
                        pass
                    pushed += 1
                else:
                    skipped += 1
            except Exception:
                skipped += 1
            # Small delay between assets to avoid hammering the server
            await asyncio.sleep(0.2)

        elapsed = time.time() - t0
        GAP_FILL_SUMMARY = (
            f"WEB PUSH c{cycle}: {pushed}/{total} pushed ({elapsed:.1f}s) | "
            f"{skipped} skipped | next in {WEB_PUSH_INTERVAL}s"
        )
        await asyncio.sleep(WEB_PUSH_INTERVAL)

def print_dashboard():
    _tf_label = "Unknown"
    for tf_tuple in TIMEFRAMES:
        mt4_p, secs, label = tf_tuple[0], tf_tuple[1], tf_tuple[2]
        if mt4_p == PERIOD and secs == PERIOD_SECONDS:
            _tf_label = label
            break
    # تبسيط العنوان: سطر واحد فاصل بدل 3 خطوط زرقاء كثيفة
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}")
    print(f"  {Colors.BOLD}QXChartMT4 Pro - v8.0  {Colors.DIM}|  @qxzero1  |  2026{Colors.RESET}")
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}")
    print(f"  {Colors.CYAN}Timeframe  {Colors.RESET}: {_tf_label} ({PERIOD_SECONDS}s)")
    print(f"  {Colors.CYAN}History    {Colors.RESET}: {HISTORY_DAYS:.2f} day = {INITIAL_CANDLES} candles")
    # FIX L11: TZ offset display
    _tz_sec = _get_tz_offset()
    _tz_sign = '+' if _tz_sec >= 0 else '-'
    _tz_h, _tz_m = divmod(abs(_tz_sec) // 60, 60)
    _tz_src = "manual" if LOCAL_TZ_OFFSET_SECONDS is not None else "system"
    print(f"  {Colors.CYAN}TZ offset  {Colors.RESET}: UTC{_tz_sign}{_tz_h:02d}:{_tz_m:02d} (source={_tz_src})")
    print(f"  {Colors.CYAN}Gap fill   {Colors.RESET}: {GAP_FILL_CANDLES} candles / {GAP_FILL_REFRESH_INTERVAL}s")
    print(f"  {Colors.GREEN}Contact    {Colors.RESET}: https://t.me/qxchart")
    print(f"  {Colors.DIM}{'─'*68}{Colors.RESET}\n")

# ==============================================================================
# WEB SERVER — Live chart dashboard (ap.py style, embedded)
# Runs on http://localhost:8765  — pairs click -> live chart
# ==============================================================================
WEB_SERVER_PORT = 8765
WEB_SERVER_HOST = "127.0.0.1"

# Shared candle store for web server (populated by realtime_stream + fetch)
_web_candle_store = {}          # pair_name -> {"candles": [...], "lastUpdate": ms, "digits": int}
_web_candle_lock = threading.RLock()
_web_push_stats = {"total_pushes": 0, "last_push_time": 0, "start_time": time.time()}

def _web_pair_name(api_symbol):
    """Convert api_symbol (e.g. AUDCAD_otc) -> display pair name (AUDCAD-OTCq)."""
    s = api_symbol.strip()
    if s.lower().endswith("_otc"):
        return s[:-4].upper() + "-OTCq"
    return s.upper()

_web_latest_tick = {}   # pair_name -> {"price": float, "time": int, "digits": int, "ts": ms}

def _web_update_asset(asset, full_resync=False):
    """Called after every candle update -- pushes data to web candle store.

    v9.0: OPTIMIZED for max-speed live ticks.
      - Default (full_resync=False): only updates _web_latest_tick (cheap, ~1µs).
        Used by realtime_stream on every tick. Does NOT copy the full candle list.
      - full_resync=True: refreshes the full _web_candle_store[pair] entry.
        Used after initial historical fetch and on candle close (new candle started).
    """
    if not asset.candles:
        return
    pair = _web_pair_name(asset.api_symbol)
    try:
        digits = asset.digits(asset.price) if asset.price else 5
    except Exception:
        digits = 5
    last_c = asset.candles[-1]
    now_ms = int(time.time() * 1000)

    # Always update the lightweight tick cache (fast path for /api/last-tick).
    # This is what the chart polls at 50ms — must be O(1).
    with _web_candle_lock:
        _web_latest_tick[pair] = {
            "price": float(asset.price) if asset.price else float(last_c.get("close", 0)),
            "time": int(last_c.get("time", 0)),
            "open": float(last_c.get("open", 0)),
            "high": float(last_c.get("high", 0)),
            "low": float(last_c.get("low", 0)),
            "close": float(last_c.get("close", 0)),
            "digits": digits,
            "ts": now_ms,
        }
        _web_push_stats["total_pushes"] += 1
        _web_push_stats["last_push_time"] = now_ms

    # Only do the heavy full-candle copy when explicitly requested.
    # realtime_stream calls _web_update_asset(asset, full_resync=True) only on
    # candle CLOSE (new candle started), not on every tick.
    if full_resync:
        candles_copy = [dict(c) for c in asset.candles[-3000:]]
        with _web_candle_lock:
            _web_candle_store[pair] = {
                "pair": pair,
                "digits": digits,
                "candles": candles_copy,
                "lastUpdate": now_ms,
            }

# == HTML & CSS (same dark theme as ap.py) =====================================
_WEB_SHARED_CSS = """
:root{--bg-primary:#0a0e17;--bg-secondary:#111827;--bg-nav:#0d1117;
      --border:#1f2937;--text:#e5e7eb;--text-dim:#9ca3af;--text-muted:#6b7280;
      --green:#22c55e;--red:#ef4444;--blue:#3b82f6;--accent:#6366f1;}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
     background:var(--bg-primary);color:var(--text);min-height:100vh;}
a{color:var(--blue);text-decoration:none;}
a:hover{text-decoration:underline;}
"""

_WEB_HOME_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0,user-scalable=yes">
<meta name="theme-color" content="#0a0e17">
<title>QXChart MT4 - Live Dashboard</title>
<style>
CSS_HERE
.header{background:var(--bg-nav);border-bottom:1px solid var(--border);
        padding:16px 24px;display:flex;align-items:center;justify-content:space-between;
        position:sticky;top:0;z-index:50;}
.logo{display:flex;align-items:center;gap:12px;}
.logo-icon{width:40px;height:40px;border-radius:12px;
           background:linear-gradient(135deg,#22c55e,#06b6d4);
           display:flex;align-items:center;justify-content:center;
           font-weight:bold;color:#000;font-size:18px;}
.logo h1{font-size:20px;font-weight:700;}
.logo p{font-size:12px;color:var(--text-muted);}
.status-badge{display:flex;align-items:center;gap:8px;
              padding:6px 12px;border-radius:20px;background:rgba(255,255,255,0.05);}
.status-dot{width:8px;height:8px;border-radius:50%;}
.status-dot.live{background:var(--green);animation:pulse 2s infinite;}
.status-dot.offline{background:var(--red);}
@keyframes pulse{0%,100%{opacity:1;}50%{opacity:0.4;}}
.status-text{font-size:12px;color:var(--text-dim);}
.main{max-width:1200px;margin:0 auto;padding:24px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
            gap:12px;margin-bottom:24px;}
.stat-card{background:var(--bg-secondary);border:1px solid var(--border);
           border-radius:12px;padding:16px;}
.stat-card .label{font-size:11px;color:var(--text-muted);margin-bottom:4px;}
.stat-card .value{font-size:24px;font-weight:700;}
.stat-card .value.green{color:var(--green);}
.stat-card .value.red{color:var(--red);}
.search-box{position:relative;margin-bottom:24px;}
.search-box input{width:100%;padding:12px 16px 12px 44px;background:var(--bg-secondary);
                  border:1px solid var(--border);border-radius:12px;color:var(--text);
                  font-size:14px;outline:none;transition:border-color 0.2s;}
.search-box input:focus{border-color:var(--blue);}
.search-box svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);
                width:20px;height:20px;color:var(--text-muted);}
.pairs-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px;}
.pair-card{background:var(--bg-secondary);border:1px solid var(--border);
           border-radius:12px;padding:16px;cursor:pointer;
           transition:all 0.2s;display:flex;align-items:center;justify-content:space-between;}
.pair-card:hover{background:#162032;border-color:rgba(59,130,246,0.5);transform:translateY(-1px);}
.pair-left{display:flex;align-items:center;gap:12px;}
.pair-flag{font-size:24px;}
.pair-name{font-weight:600;font-size:15px;}
.pair-detail{font-size:12px;color:var(--text-muted);}
.pair-right{text-align:right;}
.pair-status{font-size:11px;padding:2px 8px;border-radius:10px;display:inline-flex;
             align-items:center;gap:4px;margin-bottom:4px;}
.pair-status.live{background:rgba(34,197,94,0.1);color:var(--green);}
.pair-status.stale{background:rgba(239,68,68,0.1);color:var(--red);}
.pair-status .dot{width:6px;height:6px;border-radius:50%;display:inline-block;}
.pair-status.live .dot{background:var(--green);}
.pair-status.stale .dot{background:var(--red);}
.pair-time{font-size:11px;color:var(--text-muted);}
.empty-state{text-align:center;padding:60px 24px;}
.empty-state h3{font-size:20px;margin-bottom:8px;}
.empty-state p{color:var(--text-dim);font-size:14px;max-width:400px;margin:0 auto;}
.footer{border-top:1px solid var(--border);background:var(--bg-nav);padding:16px 24px;margin-top:32px;}
.footer-inner{max-width:1200px;margin:0 auto;display:flex;
              justify-content:space-between;font-size:12px;color:var(--text-muted);flex-wrap:wrap;gap:8px;}
@media(max-width:640px){
  .header{padding:12px 16px;flex-wrap:wrap;gap:8px;}
  .logo h1{font-size:16px;}.logo p{font-size:11px;}
  .main{padding:16px;}
  .pairs-grid{grid-template-columns:1fr;}
  .stats-grid{grid-template-columns:repeat(2,1fr);}
  .pair-card{padding:12px;}
}
</style>
</head>
<body>
<div class="header">
  <div class="logo">
    <div class="logo-icon">Q</div>
    <div><h1>QXChart MT4 Pro</h1><p>Live Quotex OTC Chart Dashboard</p></div>
  </div>
  <div class="status-badge">
    <span class="status-dot offline" id="statusDot"></span>
    <span class="status-text" id="statusText">Connecting...</span>
  </div>
</div>
<div class="main">
  <div class="stats-grid">
    <div class="stat-card"><div class="label">Active Pairs</div><div class="value" id="statPairs">0</div></div>
    <div class="stat-card"><div class="label">Total Pushes</div><div class="value" id="statPushes">0</div></div>
    <div class="stat-card"><div class="label">Last Push</div><div class="value" id="statLastPush">Never</div></div>
    <div class="stat-card"><div class="label">Status</div><div class="value red" id="statStatus">OFFLINE</div></div>
  </div>
  <div class="search-box">
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
    <input type="text" id="searchInput" placeholder="Search pairs... (e.g. USD, EUR, BDT)">
  </div>
  <div class="pairs-grid" id="pairsGrid"></div>
  <div class="empty-state" id="emptyState" style="display:none;">
    <h3>No Data Yet</h3>
    <p>Waiting for candle data from Quotex... The script is fetching history for all pairs.</p>
  </div>
</div>
<div class="footer">
  <div class="footer-inner">
    <span>QXChart MT4 Pro - Live Dashboard &copy; 2026</span>
    <span>Pairs refresh every 3s &bull; Chart updates every 1s</span>
  </div>
</div>
<script>
const FLAGS={USD:"\u{1F1FA}\u{1F1F8}",EUR:"\u{1F1EA}\u{1F1FA}",GBP:"\u{1F1EC}\u{1F1E7}",JPY:"\u{1F1EF}\u{1F1F5}",AUD:"\u{1F1E6}\u{1F1FA}",NZD:"\u{1F1F3}\u{1F1FF}",CAD:"\u{1F1E8}\u{1F1E6}",CHF:"\u{1F1E8}\u{1F1ED}",BDT:"\u{1F1E7}\u{1F1E9}",ARS:"\u{1F1E6}\u{1F1F7}",INR:"\u{1F1EE}\u{1F1F3}",MXN:"\u{1F1F2}\u{1F1FD}",PHP:"\u{1F1F5}\u{1F1ED}",PKR:"\u{1F1F5}\u{1F1F0}",NGN:"\u{1F1F3}\u{1F1EC}",COP:"\u{1F1E8}\u{1F1F4}",IDR:"\u{1F1EE}\u{1F1E9}",EGP:"\u{1F1EA}\u{1F1EC}",DZD:"\u{1F1E9}\u{1F1FF}",BRL:"\u{1F1E7}\u{1F1F7}",ZAR:"\u{1F1FF}\u{1F1E6}"};
function getFlag(pair){const base=pair.replace(/-OTCq?$/,"").replace(/[-_].*$/,"");const codes=Object.keys(FLAGS).sort((a,b)=>b.length-a.length);let rem=base,f=[];for(const c of codes){if(rem.startsWith(c)){f.push(FLAGS[c]);rem=rem.slice(c.length);}}return f.join("")||"\u{1F4B1}";}
function cleanName(p){return p.replace("-OTCq"," (OTC)").replace("-OTC"," (OTC)");}
function timeSince(ts){if(!ts)return"Never";const d=Math.floor((Date.now()-ts)/1000);if(d<3)return"Just now";if(d<60)return d+"s ago";if(d<3600)return Math.floor(d/60)+"m ago";return Math.floor(d/3600)+"h ago";}
async function loadPairs(){
  try{
    const r=await fetch("/api/pairs",{cache:"no-store"});
    const d=await r.json();
    if(d.status==="OK"){
      const pairs=d.pairs||[];const stats=d.stats||{};
      document.getElementById("statPairs").textContent=pairs.length;
      document.getElementById("statPushes").textContent=(stats.totalPushes||0).toLocaleString();
      document.getElementById("statLastPush").textContent=timeSince(stats.lastPushTime);
      const isLive=stats.isLive;
      document.getElementById("statusDot").className="status-dot "+(isLive?"live":"offline");
      document.getElementById("statusText").textContent=isLive?"LIVE":"Waiting for data...";
      const sv=document.getElementById("statStatus");
      sv.textContent=isLive?"LIVE":"OFFLINE";sv.className="value "+(isLive?"green":"red");
      const search=document.getElementById("searchInput").value.toLowerCase();
      const filtered=pairs.filter(p=>p.pair.toLowerCase().includes(search));
      const grid=document.getElementById("pairsGrid");
      const empty=document.getElementById("emptyState");
      if(pairs.length===0){grid.innerHTML="";empty.style.display="block";return;}
      empty.style.display="none";
      if(filtered.length===0&&search){grid.innerHTML='<div style="text-align:center;padding:40px;color:var(--text-dim);">No pairs matching "'+search+'"</div>';return;}
      grid.innerHTML=filtered.map(p=>{
        const live=Date.now()-p.lastUpdate<10000;
        return '<a href="/pairs='+encodeURIComponent(p.pair)+'" class="pair-card">'
          +'<div class="pair-left"><span class="pair-flag">'+getFlag(p.pair)+'</span>'
          +'<div><div class="pair-name">'+cleanName(p.pair)+'</div>'
          +'<div class="pair-detail">'+(p.candleCount||0)+' candles</div></div></div>'
          +'<div class="pair-right">'
          +'<div class="pair-status '+(live?"live":"stale")+'"><span class="dot"></span>'+(live?"Live":"Stale")+'</div>'
          +'<div class="pair-time">'+timeSince(p.lastUpdate)+'</div></div></a>';
      }).join("");
    }
  }catch(e){console.error(e);}
}
loadPairs();
setInterval(loadPairs,3000);
document.getElementById("searchInput").addEventListener("input",loadPairs);
</script>
</body>
</html>"""

_WEB_CHART_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=5.0,user-scalable=yes,viewport-fit=cover">
<meta name="theme-color" content="#0a0e17">
<title>PAIR_DISPLAY - Live Chart | QXChart MT4</title>
<!-- ===== Lightweight Charts (TradingView) ~45KB, no jQuery/React ===== -->
<script src="https://unpkg.com/lightweight-charts@4.1.3/dist/lightweight-charts.standalone.production.js"></script>
<style>
CSS_HERE
html,body{height:100%;width:100%;overflow:hidden;}
body{height:100vh;display:flex;flex-direction:column;overflow:hidden;}
.nav{display:flex;align-items:center;gap:10px;padding:10px 16px;
     background:var(--bg-nav);border-bottom:1px solid var(--border);flex-shrink:0;}
.nav-back{color:var(--text-dim);display:flex;text-decoration:none;}
.nav-back:hover{color:#fff;}
.nav-sep{width:1px;height:16px;background:var(--border);}
.nav-brand{font-size:13px;color:var(--text-dim);}
.chart-header{display:flex;align-items:center;padding:12px 16px;
              background:var(--bg-nav);border-bottom:1px solid var(--border);
              flex-shrink:0;flex-wrap:wrap;gap:8px 16px;}
.chart-header-left{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;flex:1;}
.pair-title{font-size:18px;font-weight:700;white-space:nowrap;}
.current-price{font-size:24px;font-weight:700;font-family:'SF Mono','Fira Code',monospace;white-space:nowrap;transition:color 300ms ease;}
.price-change{font-size:13px;font-weight:600;font-family:monospace;white-space:nowrap;}
.price-change.up{color:var(--green);}
.price-change.down{color:var(--red);}
.chart-wrap{flex:1;position:relative;background:var(--bg-primary);min-height:0;width:100%;overflow:hidden;}
#chartContainer{position:absolute;inset:0;width:100%;height:100%;}
.overlay{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;
         background:rgba(10,14,23,0.92);z-index:10;}
.overlay-box{text-align:center;padding:24px;max-width:400px;}
.spinner{width:48px;height:48px;border:3px solid var(--blue);border-top-color:transparent;
         border-radius:50%;animation:spin 1s linear infinite;margin:0 auto 16px;}
@keyframes spin{to{transform:rotate(360deg);}}
.overlay p{font-size:14px;color:var(--text-dim);}
@media(max-width:380px){.nav{padding:6px 10px;}.chart-header{padding:8px 10px;}.pair-title{font-size:14px;}.current-price{font-size:18px;}}
@media(max-width:600px){.pair-title{font-size:16px;}.current-price{font-size:20px;}}
</style>
</head>
<body>
<div class="nav">
  <a href="/" class="nav-back"><svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7"/></svg></a>
  <div class="nav-sep"></div>
  <span class="nav-brand">QXChart MT4 Pro</span>
</div>
<div class="chart-header">
  <div class="chart-header-left">
    <span class="pair-title" id="pairTitle">PAIR_DISPLAY</span>
    <span class="current-price" id="currentPrice">---</span>
    <span class="price-change" id="priceChange"></span>
  </div>
</div>
<div class="chart-wrap">
  <div id="chartContainer"></div>
  <div class="overlay" id="loadingOverlay">
    <div class="overlay-box">
      <div class="spinner"></div>
      <p>Loading chart data...</p>
    </div>
  </div>
</div>
<script>
// ===== Lightweight Charts (TradingView) — Same dark theme as the rest of the app =====
const PAIR_NAME = "PAIR_NAME_RAW";
let candles = [];       // [{t, open, high, low, close}]
let digits = 5;
let lastBarTime = 0;     // last candle time we fed to the series (for series.update)
let initialized = false;

// Colors (match the existing palette)
const C = {
  bg:"#0a0e17", grid:"#1a2235", up:"#22c55e", down:"#ef4444",
  text:"#9ca3af", textBright:"#e5e7eb", crosshair:"rgba(255,255,255,0.3)",
  border:"#1f2937"
};

// ===== Create chart =====
const container = document.getElementById("chartContainer");
const chart = LightweightCharts.createChart(container, {
  layout: {
    background: { type: 'solid', color: C.bg },
    textColor: C.text,
    fontSize: 11,
    fontFamily: "'SF Mono','Fira Code',monospace"
  },
  grid: {
    vertLines: { color: C.grid, style: 1 },
    horzLines: { color: C.grid, style: 1 }
  },
  crosshair: {
    mode: LightweightCharts.CrosshairMode.Normal,
    vertLine: { color: C.crosshair, width: 1, style: 2, labelBackgroundColor: "#3b82f6" },
    horzLine: { color: C.crosshair, width: 1, style: 2, labelBackgroundColor: "#3b82f6" }
  },
  rightPriceScale: {
    borderColor: C.border,
    scaleMargins: { top: 0.08, bottom: 0.08 }
  },
  timeScale: {
    borderColor: C.border,
    timeVisible: true,
    secondsVisible: false,
    rightOffset: 4,
    barSpacing: 8
  },
  handleScroll: true,
  handleScale: true,
  autoSize: true
});

// ===== Candlestick series =====
const series = chart.addCandlestickSeries({
  upColor: C.up,
  downColor: C.down,
  borderUpColor: C.up,
  borderDownColor: C.down,
  wickUpColor: C.up,
  wickDownColor: C.down,
  borderVisible: false,
  priceFormat: { type: 'price', precision: digits, minMove: 0.00001 }
});

// Current price line (dashed, colored by last candle direction)
const priceLine = series.createPriceLine({
  price: 0,
  color: C.up,
  lineWidth: 1,
  lineStyle: LightweightCharts.LineStyle.Dashed,
  axisLabelVisible: true,
  title: ''
});

// ===== Helpers =====
function fmtPrice(p){ return Number(p).toFixed(digits); }

function updatePriceLine(){
  if(candles.length === 0) return;
  const last = candles[candles.length - 1];
  const isUp = last.close >= last.open;
  // Remove and recreate to update color (Lightweight Charts limitation)
  series.removePriceLine(priceLine);
  const newLine = series.createPriceLine({
    price: last.close,
    color: isUp ? C.up : C.down,
    lineWidth: 1,
    lineStyle: LightweightCharts.LineStyle.Dashed,
    axisLabelVisible: true,
    title: ''
  });
  // Replace reference (we re-declare via the variable name)
  // Note: cannot reassign const, so we keep using a function-local approach below
}

function refreshPriceLine(){
  if(candles.length === 0) return;
  const last = candles[candles.length - 1];
  const isUp = last.close >= last.open;
  // Simpler: remove all price lines and add a new one each tick
  // (Lightweight Charts does not allow updating an existing price line in place)
  // We track it via a module-level variable
  if(window._activePriceLine){
    try { series.removePriceLine(window._activePriceLine); } catch(e){}
  }
  window._activePriceLine = series.createPriceLine({
    price: last.close,
    color: isUp ? C.up : C.down,
    lineWidth: 1,
    lineStyle: LightweightCharts.LineStyle.Dashed,
    axisLabelVisible: true,
    title: ''
  });
}

function updatePriceHeader(){
  if(!candles || candles.length === 0) return;
  const last = candles[candles.length - 1];
  const first = candles[0];
  const priceEl = document.getElementById("currentPrice");
  const changeEl = document.getElementById("priceChange");
  const newP = Number(last.close).toFixed(digits);
  if(priceEl){
    if(priceEl.textContent !== newP && priceEl.textContent !== "---"){
      priceEl.style.color = last.close >= last.open ? "#22c55e" : "#ef4444";
      setTimeout(() => { priceEl.style.color = ""; }, 300);
    }
    priceEl.textContent = newP;
  }
  if(changeEl){
    const change = last.close - first.open;
    const pct = first.open > 0 ? (change / first.open * 100) : 0;
    const sign = change >= 0 ? "+" : "";
    changeEl.textContent = sign + change.toFixed(digits) + " (" + sign + pct.toFixed(2) + "%)";
    changeEl.className = "price-change " + (change >= 0 ? "up" : "down");
  }
  refreshPriceLine();
}

// ===== Data fetching =====
async function fetchFullCandles(){
  try{
    const r = await fetch("/api/candles?pair=" + encodeURIComponent(PAIR_NAME), {cache:"no-store"});
    if(!r.ok) return;
    const data = await r.json();
    if(data.status === "OK" && data.candles && data.candles.length > 0){
      digits = data.digits || 5;
      // Update price format precision
      series.applyOptions({ priceFormat: { type: 'price', precision: digits, minMove: Math.pow(10, -digits) } });
      // Normalize: API sends {t, open, high, low, close}
      // Lightweight Charts expects {time, open, high, low, close}
      let raw = data.candles.map(c => ({
        time: Number(c.t || c.time || 0),
        open: Number(c.open), high: Number(c.high),
        low: Number(c.low), close: Number(c.close)
      })).filter(c => c.time > 0 && c.open > 0);
      raw.sort((a,b) => a.time - b.time);
      // Deduplicate by time (Lightweight Charts requires strictly ascending unique times)
      const seen = new Set();
      raw = raw.filter(c => { if(seen.has(c.time)) return false; seen.add(c.time); return true; });

      candles = raw;
      if(candles.length > 0){
        lastBarTime = candles[candles.length - 1].time;
      }

      // Push to series
      series.setData(candles);

      // Hide loading overlay
      const ol = document.getElementById("loadingOverlay");
      if(ol && candles.length > 0) ol.style.display = "none";

      // Fit content on first load, then keep the latest view
      if(!initialized){
        chart.timeScale().fitContent();
        initialized = true;
      }

      updatePriceHeader();
    }
  } catch(e){ console.error("[Chart] fetch error:", e); }
}

async function fetchLiveTick(){
  try{
    const r = await fetch("/api/last-tick?pair=" + encodeURIComponent(PAIR_NAME), {cache:"no-store"});
    if(!r.ok) return;
    const d = await r.json();
    if(d.status === "OK" && d.time && d.open){
      const t = Number(d.time);
      const tick = {
        time: t, open: Number(d.open), high: Number(d.high),
        low: Number(d.low), close: Number(d.close)
      };
      if(t > 0 && tick.open > 0 && candles.length > 0){
        const last = candles[candles.length - 1];
        if(t === last.time){
          // Update current candle in place
          last.high = Math.max(last.high, tick.high);
          last.low = Math.min(last.low, tick.low);
          last.close = tick.close;
          series.update(last);
        } else if(t > last.time){
          candles.push(tick);
          lastBarTime = t;
          series.update(tick);
        }
        updatePriceHeader();
      }
    }
  } catch(e){}
}

// Start
fetchFullCandles();
// v9.0: MAX-SPEED polling intervals.
//   - fetchLiveTick: 300ms -> 50ms (20 ticks/sec, near-instant chart updates)
//     This is the hot path: the dashboard polls /api/last-tick for the live price.
//   - fetchFullCandles: 3000ms -> 500ms (rare full resync; the live tick path
//     handles 99% of updates). 500ms is enough to catch missed candles without
//     hammering the Flask server.
// Note: these are CLIENT-side polls to the local Flask server. The Flask server
// itself receives updates from realtime_stream at STREAM_POLL_INTERVAL=0.05s.
setInterval(fetchFullCandles, 500);
setInterval(fetchLiveTick, 50);
</script>
</body>
</html>"""

# == Flask Web Server ==========================================================
def _build_web_flask_app():
    """Build and return Flask app for the embedded web server."""
    if not HAS_FLASK:
        return None

    web_app = Flask(__name__)

    @web_app.route("/")
    def web_home():
        html = _WEB_HOME_HTML.replace("CSS_HERE", _WEB_SHARED_CSS)
        return Response(html, content_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store, no-cache"})

    @web_app.route("/pairs=<path:pair_name>")
    def web_pair_chart(pair_name):
        pair_name = pair_name.strip()
        display = pair_name.replace("-OTCq", " (OTC)").replace("-OTC", " (OTC)")
        html = _WEB_CHART_HTML.replace("PAIR_NAME_RAW", pair_name)
        html = html.replace("PAIR_DISPLAY", display)
        html = html.replace("CSS_HERE", _WEB_SHARED_CSS)
        return Response(html, content_type="text/html; charset=utf-8",
                        headers={"Cache-Control": "no-store, no-cache"})

    @web_app.route("/api/pairs")
    def web_api_pairs():
        with _web_candle_lock:
            pairs_data = []
            for name, data in sorted(_web_candle_store.items()):
                pairs_data.append({
                    "pair": name,
                    "lastUpdate": data.get("lastUpdate", 0),
                    "candleCount": len(data.get("candles", [])),
                })
        last_push = _web_push_stats.get("last_push_time", 0)
        is_live = last_push > 0 and (int(time.time() * 1000) - last_push) < 10000
        result = {
            "status": "OK",
            "pair_count": len(pairs_data),
            "pairs": pairs_data,
            "stats": {
                "totalPushes": _web_push_stats.get("total_pushes", 0),
                "lastPushTime": last_push,
                "isLive": is_live,
            },
        }
        resp = Response(json.dumps(result, separators=(",", ":")),
                        content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/candles")
    def web_api_candles():
        pair = flask_request.args.get("pair", "").strip()
        if not pair:
            return Response(json.dumps({"status": "ERROR", "error": "Missing pair", "candles": []}),
                            content_type="application/json", status=400)
        with _web_candle_lock:
            data = _web_candle_store.get(pair)
            if data is None:
                pair_lower = pair.lower()
                for k, v in _web_candle_store.items():
                    if k.lower() == pair_lower:
                        data = v
                        break
        if data is None:
            return Response(json.dumps({"status": "ERROR", "error": f"No data for {pair}", "candles": []}),
                            content_type="application/json", status=404)
        candles = data.get("candles", [])
        chart_candles = [{"t": int(c["time"]), "open": c["open"], "high": c["high"],
                          "low": c["low"], "close": c["close"]} for c in candles]
        result = {
            "status": "OK",
            "pair": pair,
            "digits": data.get("digits", 5),
            "candle_count": len(chart_candles),
            "candles": chart_candles,
        }
        resp = Response(json.dumps(result, separators=(",", ":")), content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/last-tick")
    def web_api_last_tick():
        """Returns only the latest tick for a pair (very lightweight, for real-time updates)."""
        pair = flask_request.args.get("pair", "").strip()
        if not pair:
            return Response(json.dumps({"status": "ERROR", "error": "Missing pair"}),
                            content_type="application/json", status=400)
        with _web_candle_lock:
            tick = _web_latest_tick.get(pair)
            if tick is None:
                pair_lower = pair.lower()
                for k, v in _web_latest_tick.items():
                    if k.lower() == pair_lower:
                        tick = v
                        break
        if tick is None:
            return Response(json.dumps({"status": "WAIT"}),
                            content_type="application/json", status=200)
        result = {"status": "OK", "pair": pair, **tick}
        resp = Response(json.dumps(result, separators=(",", ":")), content_type="application/json")
        resp.headers["Cache-Control"] = "no-cache"
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp

    @web_app.route("/api/health")
    def web_health():
        with _web_candle_lock:
            pair_count = len(_web_candle_store)
        return Response(json.dumps({"status": "OK", "pairs": pair_count,
                                    "uptime": int(time.time() - _web_push_stats["start_time"])}),
                        content_type="application/json")

    import logging as _logging
    _logging.getLogger("werkzeug").setLevel(_logging.ERROR)
    return web_app


def _start_web_server():
    """Start the Flask web server in a daemon thread."""
    if not HAS_FLASK:
        print(f"\n{Colors.DIM}[WebServer] Flask not installed -- no dashboard."
              f"  pip install flask{Colors.RESET}")
        return
    web_app = _build_web_flask_app()
    if web_app is None:
        return

    def _run():
        try:
            web_app.run(host=WEB_SERVER_HOST, port=WEB_SERVER_PORT,
                        debug=False, use_reloader=False, threaded=True)
        except OSError as e:
            if "Address already in use" in str(e) or "10048" in str(e):
                logmsg(f"[WebServer] Port {WEB_SERVER_PORT} already in use -- skipping dashboard")
            else:
                logmsg(f"[WebServer] Failed to start: {e}")
        except Exception as e:
            logmsg(f"[WebServer] Error: {e}")

    t = threading.Thread(target=_run, name="WebDashboard", daemon=True)
    t.start()
    time.sleep(0.6)
    print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}")
    print(f"{Colors.GREEN}  [WebServer] Dashboard running at:{Colors.RESET}")
    print(f"{Colors.BOLD}  http://{WEB_SERVER_HOST}:{WEB_SERVER_PORT}/{Colors.RESET}")
    print(f"{Colors.DIM}  Click any pair card to view its live chart{Colors.RESET}")
    print(f"{Colors.GREEN}{'='*60}{Colors.RESET}\n")



#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BINOLLA — Binolla Candle Fetcher (نسخة مبسّطة)
=====================================================
يتصل بمنصة Binolla (https://binolla.com/ar/) عبر WebSocket
باستخدام بروتوكول Socket.IO v4 / Engine.IO v4:

    wss://ws3.binolla.com/socket.io/?EIO=4&transport=websocket

يدعم:
  - **تسجيل دخول HTTP بالإيميل/كلمة المرور** بنفس بنية qx__1.py:
      * Browser(Session) + CipherSuiteAdapter (TLS fingerprinting يحاكي Chrome)
      * Login(Browser)  : GET /login → استخراج CSRF → POST form data
                          (email, password, remember) → استخراج JWT
      * Settings(Browser) : GET /api/state و /api/dictionaries
  - مصادقة JWT عبر WebSocket (42["authorization",{token,...}]).
  - استلام الرسائل الثنائية (binary events بصيغة 451-[...]).
  - جلب: الأصول، الأرصدة، الإعدادات، الطلبات المفتوحة/المغلقة،
    التنبيهات، الشموع التاريخية، الاقتباسات اللحظية (quotes).
  - تغيير الأصل والفريم عبر asset/list/change.
  - وضع صفقات (binary options) عبر orders/open.
  - حفظ الإيميل/كلمة المرور والتوكن في credentials.json.

البروتوكول باختصار:
  - 0{...}        Engine.IO OPEN  (sid, pingInterval=25s, pingTimeout=20s)
  - 40            Socket.IO CONNECT (من العميل إلى الخادم)
  - 40{...}       Socket.IO CONNECT_ACK (من الخادم)
  - 42[event,data] Socket.IO EVENT (نصّي)
  - 451-[event,{_placeholder:true,num:0}]  Socket.IO BINARY EVENT
                                              (متبوع بإطار ثنائي واحد)
  - 2 / 3         Engine.IO PING / PONG (الخادم يرسل 2، العميل يردّ بـ 3)

حقول نموذج تسجيل الدخول في https://binolla.com/login:
  - input[name="email"]     (type=text,    id ديناميكي مثل :r0:)
  - input[name="password"]  (type=password, id ديناميكي مثل :r1:)
  - input[name="remember"]  (type=checkbox)
  - input[name="cf-turnstile-response"]  (مخفي — Cloudflare CAPTCHA)

ملاحظة: الـ IDs ديناميكية، لذا نعتمد على `name` فقط (كما في qx__1.py).

الاستخدام:
    python bn__1.py
  ثم أدخل الإيميل وكلمة المرور (تُحفظ تلقائياً في credentials.json).

  أو بصيغة non-interactive:
    BINOLLA_EMAIL="you@example.com" BINOLLA_PASSWORD="secret" \\
        python bn__1.py --asset EURUSD_otc --period 1 --days 7 -y
"""

import os
import sys
import ssl
import json
import time
import random
import shutil
import logging
import asyncio
import threading
import traceback
import itertools
import contextlib
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

import certifi
import requests
import websocket
from bs4 import BeautifulSoup
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import orjson as _orjson
    HAS_ORJSON = True
except Exception:
    HAS_ORJSON = False

# ==============================================================================
# SECTION 0: CONFIG & CONSTANTS
# ==============================================================================
BN_HOST = "binolla.com"
BN_WS_HOST = "ws3.binolla.com"
BN_ORIGIN_URL = f"https://{HOST}"
BN_WSS_URL = f"wss://{BN_WS_HOST}/socket.io/?EIO=4&transport=websocket"

BN_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# إعدادات TLS fingerprinting (تحاكي Chrome) لتجاوز اكتشاف البوتات البسيط
DEFAULT_CIPHER_SUITE = (
    'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:'
    'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:'
    'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:'
    'DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384'
)
DEFAULT_ECDH_CURVE = 'prime256v1'

# استراتيجية إعادة المحاولة لطلبات HTTP
retry_strategy = Retry(
    total=3,
    backoff_factor=0.5,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET", "POST"],
)

BN_BN_CREDENTIALS_FILE = Path("credentials.json")
BN_BN_DATA_DIR = Path("binolla_data")
BN_DATA_DIR.mkdir(exist_ok=True)
BN_BN_LOG_FILE = Path("binolla.log")

# إعدادات الجلب
FETCH_CHUNK_SIZE = 200          # عدد الشموع لكل batch
FETCH_BATCH_DELAY = 0.10        # ثانية بين الـ batches
MAX_FETCH_RETRIES = 5
RETRY_BACKOFF_BASE = 2
RETRY_BACKOFF_MAX = 15
KEEPALIVE_INTERVAL = 5          # ping كل 5 ثوان للحفاظ على الاتصال

_request_counter = itertools.count(int(time.time() * 1000))

# ==============================================================================
# SECTION 1: LOGGING
# ==============================================================================
# علم عام: إن كان True، logmsg ستطبع سطراً جديداً قبل كل رسالة لتفادي
# الكتابة فوق بث الأسعار اللحظي. يُضبط من LivePriceStream.
_LIVE_STREAM_ACTIVE = False


def set_live_stream_active(active: bool) -> None:
    global _LIVE_STREAM_ACTIVE
    _LIVE_STREAM_ACTIVE = active


def bn_bn_logmsg(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    # إن كان البث اللحظي نشطاً، اطبع على سطر جديد أولاً لتفادي الكتابة فوق السعر
    if _LIVE_STREAM_ACTIVE:
        sys.stdout.write("\n")
    print(f"  \033[2m[{ts}]\033[0m {msg}")
    try:
        with open(BN_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def bn_bn_log_exception(context: str, exc: BaseException) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    try:
        with open(BN_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}\n")
    except Exception:
        pass


# إعداد سكّت WebSocket
def _bn_bn_prepare_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    ws_logger = logging.getLogger("websocket")
    ws_logger.setLevel(logging.WARNING)
    ws_logger.addHandler(logging.NullHandler())


_bn_prepare_logging()
logger = logging.getLogger("binolla")
cacert = certifi.where()
ssl_context = ssl.create_default_context(cafile=cacert)


class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    YELLOW = '\033[93m'
    CYAN = '\033[96m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


def _thread_excepthook(args):
    bn_log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook


def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    bn_log_exception("main thread (top level)", exc_value)
sys.excepthook = _main_excepthook


# ==============================================================================
# SECTION 2: ASYNC HELPERS
# ==============================================================================
async def wait_until(predicate: Callable[[], bool], *, timeout: float = 10.0,
                     step: float = 0.05) -> None:
    async def _loop():
        while not predicate():
            await asyncio.sleep(step)
    try:
        await asyncio.wait_for(_loop(), timeout=timeout)
    except asyncio.TimeoutError:
        raise


async def wait_for_first_event(*events: asyncio.Event, timeout: float = 10.0) -> int:
    """يُنتظر أول event يُطلق من القائمة، ويُعيد إنديكسه. يرفع TimeoutError عند انتهاء المهلة."""
    tasks = [asyncio.ensure_future(e.wait()) for e in events]
    try:
        done, pending = await asyncio.wait(tasks, timeout=timeout,
                                           return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        if not done:
            raise asyncio.TimeoutError()
        completed = tasks.index(next(iter(done)))
        return completed
    except asyncio.TimeoutError:
        raise


def _schedule_event_set(event: Optional[asyncio.Event],
                        loop: Optional[asyncio.AbstractEventLoop]) -> None:
    if event is None or loop is None:
        return
    if loop.is_running():
        asyncio.run_coroutine_threadsafe(
            asyncio.wait_for(_set_event_async(event), 0.001), loop)
    else:
        try:
            event.set()
        except Exception:
            pass


async def _set_event_async(event: asyncio.Event) -> None:
    event.set()


# ==============================================================================
# SECTION 2.5: HTTP NAVIGATOR (Browser + CipherSuiteAdapter)
# ==============================================================================
# مطابق لـ qx__1.py — يستخدم ترتيب Cipher Suites يحاكي Chrome،
# مما يساعد على تجاوز اكتشاف البوتات البسيط في Cloudflare/CDN.

class CipherSuiteAdapter(HTTPAdapter):
    """HTTPAdapter مخصّص يضبط TLS cipher suites و ECDH curve لمحاكاة Chrome."""
    __attrs__ = ['ssl_context', 'max_retries', 'config', '_pool_connections',
                 '_pool_maxsize', '_pool_block', 'source_address']

    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context', None)
        self.cipherSuite = kwargs.pop('cipherSuite', DEFAULT_CIPHER_SUITE)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        self.ecdhCurve = kwargs.pop('ecdhCurve', DEFAULT_ECDH_CURVE)
        if not self.ssl_context:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            self.ssl_context.orig_wrap_socket = self.ssl_context.wrap_socket
            self.ssl_context.wrap_socket = self.wrap_socket
        if self.server_hostname:
            self.ssl_context.server_hostname = self.server_hostname
        if self.cipherSuite:
            self.ssl_context.set_ciphers(self.cipherSuite)
            self.ssl_context.set_ecdh_curve(self.ecdhCurve)
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        super().__init__(*args, **kwargs)

    def wrap_socket(self, *args, **kwargs):
        if hasattr(self.ssl_context, 'server_hostname') and self.ssl_context.server_hostname:
            kwargs['server_hostname'] = self.ssl_context.server_hostname
            self.ssl_context.check_hostname = False
        else:
            self.ssl_context.check_hostname = True
        return self.ssl_context.orig_wrap_socket(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        kwargs['source_address'] = self.source_address
        return super().init_poolmanager(*args, **kwargs)


class Browser(Session):
    """جلسة HTTP مع TLS fingerprinting. مطابق لـ qx__1.py Browser."""

    def __init__(self, *args, **kwargs):
        self.response = None
        self.default_headers = None
        self.ecdhCurve = kwargs.pop('ecdhCurve', DEFAULT_ECDH_CURVE)
        self.cipherSuite = kwargs.pop('cipherSuite', DEFAULT_CIPHER_SUITE)
        self.source_address = kwargs.pop('source_address', None)
        self.server_hostname = kwargs.pop('server_hostname', None)
        _proxies = kwargs.pop('proxies', None)
        super().__init__(*args, **kwargs)
        self.proxies = _proxies or {}
        self.headers.update(self.get_headers())
        self.mount('https://', CipherSuiteAdapter(
            ecdhCurve=self.ecdhCurve, cipherSuite=self.cipherSuite,
            server_hostname=self.server_hostname, source_address=self.source_address,
            ssl_context=ssl_context, max_retries=retry_strategy))

    def __enter__(self): return self
    def __exit__(self, exc_type, exc_val, exc_tb): self.close()
    async def __aenter__(self): return self
    async def __aexit__(self, exc_type, exc_val, exc_tb): self.__exit__(exc_type, exc_val, exc_tb)

    def get_headers(self):
        self.default_headers = {"User-Agent": USER_AGENT}
        return self.default_headers

    def set_headers(self, headers=None):
        self.headers.update(self.default_headers)
        if headers: self.headers.update(headers)

    def get_cookies(self):
        return '; '.join(f'{i.name}={i.value}' for i in self.cookies)

    def get_soup(self):
        if self.response and not self.response.ok:
            raise RuntimeError(self.response.reason)
        return BeautifulSoup(self.response.content, "html.parser")

    def send_request(self, method, url, headers=None, **kwargs):
        merged_headers = self.headers.copy()
        if headers: merged_headers.update(headers)
        if self.proxies: kwargs['proxies'] = self.proxies
        self.response = self.request(method, url, headers=merged_headers, **kwargs)
        return self.response


# ==============================================================================
# SECTION 3: STATES & ENUMS
# ==============================================================================
class WebsocketStatus(IntEnum):
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    ERROR = 3


class AuthStatus(IntEnum):
    NONE = 0
    PENDING = 1
    AUTHENTICATED = 2
    FAILED = 3


class ConnectionState:
    """حالة الاتصال المشتركة بين العميل والـ API."""
    def __init__(self):
        self.SSID: Optional[str] = None
        self.userAccountType: int = 1   # 1 = demo, 0 = real
        self.status: WebsocketStatus = WebsocketStatus.DISCONNECTED
        self.auth_status: AuthStatus = AuthStatus.NONE

        # أحداث async
        self.ws_connected_event: Optional[asyncio.Event] = None
        self.ws_closed_event: Optional[asyncio.Event] = None
        self.ws_error_event: Optional[asyncio.Event] = None
        self.auth_accepted_event: Optional[asyncio.Event] = None
        self.auth_rejected_event: Optional[asyncio.Event] = None

        # أعلام بسيطة
        self.check_websocket_if_connect: Optional[int] = None
        self.check_websocket_if_error: bool = False
        self.websocket_error_reason: Optional[str] = None
        self.check_accepted_connection: bool = False
        self.check_rejected_connection: bool = False

        # قفل داخلي لمنع التضارب
        self.ssl_Mutual_exclusion: bool = False
        self.ssl_Mutual_exclusion_write: bool = False

        # loop خارجي (من العميل async)
        self._loop: Optional[asyncio.AbstractEventLoop] = None

    def init_events(self) -> None:
        self.ws_connected_event = asyncio.Event()
        self.ws_closed_event = asyncio.Event()
        self.ws_error_event = asyncio.Event()
        self.auth_accepted_event = asyncio.Event()
        self.auth_rejected_event = asyncio.Event()

    def reset_events(self) -> None:
        for ev in (self.ws_connected_event, self.ws_closed_event,
                   self.ws_error_event, self.auth_accepted_event,
                   self.auth_rejected_event):
            if ev is not None:
                ev.clear()

    def signal_ws_connected(self):
        _schedule_event_set(self.ws_connected_event, self._loop)

    def signal_ws_closed(self):
        _schedule_event_set(self.ws_closed_event, self._loop)

    def signal_auth_accepted(self):
        _schedule_event_set(self.auth_accepted_event, self._loop)

    def signal_auth_rejected(self):
        _schedule_event_set(self.auth_rejected_event, self._loop)

    def signal_ws_error(self):
        _schedule_event_set(self.ws_error_event, self._loop)


# ==============================================================================
# SECTION 4: SOCKET.IO v4 PACKET PARSER
# ==============================================================================
def _detect_packet_type(msg_str: str) -> Tuple[str, Optional[str]]:
    """يُحلّل أول 1-2 محارف من رسالة Engine.IO v4.

    يُعيد (engine_code, payload_or_None).
    مثلاً:
      '0{"sid":...}'     -> ('0', '{"sid":...}')
      '40'               -> ('40', '')
      '42["tick"]'       -> ('42', '["tick"]')
      '451-["s_assets/list",{...}]' -> ('451-', '["s_assets/list",{...}]')
      '2'                -> ('2', None)  # PING from server
      '3'                -> ('3', None)  # PONG from server
    """
    if not msg_str:
        return ('', None)
    # Binary event / binary ack — الصيغة: 4 5 N - <json>
    # حيث N = عدد المُرفقات
    if len(msg_str) >= 4 and msg_str[0] == '4' and msg_str[1] == '5' \
            and msg_str[2].isdigit() and msg_str[3] == '-':
        return ('45' + msg_str[2] + '-', msg_str[4:])
    # 4 + 2 digits socket.io namespace + 1 message (نادر جداً في Binolla)
    if len(msg_str) >= 3 and msg_str[0] == '4' and msg_str[1].isdigit():
        return (msg_str[:2], msg_str[2:])
    # 4 + 1 char (40, 41, 42, 43, 46)  — most common
    if len(msg_str) >= 2 and msg_str[0] == '4':
        return (msg_str[:2], msg_str[2:] if len(msg_str) > 2 else '')
    # Engine.IO codes 0, 1, 2, 3, 6 (noop/no probe upgrade)
    return (msg_str[0], msg_str[1:] if len(msg_str) > 1 else None)


def _safe_json_loads(s: Union[str, bytes]) -> Any:
    """يحاول فك JSON بأمان. يدعم أو حل أو JSON قياسي."""
    if isinstance(s, bytes):
        try:
            s = s.decode("utf-8", errors="ignore")
        except Exception:
            return None
    if not s:
        return None
    if HAS_ORJSON:
        try:
            return _orjson.loads(s)
        except Exception:
            pass
    try:
        return json.loads(s)
    except Exception:
        return None


# ==============================================================================
# SECTION 5: WEBSOCKET CLIENT (EIO=4, Socket.IO v4)
# ==============================================================================
class BinollaWebsocketClient:
    """عميل WebSocket لمنصة Binolla مع دعم الرسائل الثنائية."""

    # ملف تسجيل كل رسائل WebSocket (واردة + صادرة) — يُفتح lazily
    _ws_log_file = None
    _ws_log_path: Optional[Path] = None

    def __init__(self, api: "BinollaAPI"):
        self.api = api
        self.state = api.state
        self.headers = {
            "User-Agent": USER_AGENT,
            "Origin": ORIGIN_URL,
            "Host": WS_HOST,
        }
        self.wss = websocket.WebSocketApp(
            WSS_URL,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close,
            on_open=self.on_open,
            on_ping=self.on_ping,
            on_pong=self.on_pong,
            header=self.headers,
            cookie=self.api.session_data.get("cookies"),
        )

        # ----- حالة استقبال الرسائل الثنائية -----
        self._binary_packet_queue: List[Dict] = []

        # إعدادات heartbeat
        self._ping_interval = 25.0
        self._ping_timeout = 20.0
        self._last_server_ping_at: float = time.time()

        # ----- ملف تسجيل كامل لكل رسائل WebSocket -----
        # اسم الملف يضمّن timestamp البدء حتى لا تُكتب فوقه جلسات سابقة
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        BinollaWebsocketClient._ws_log_path = Path(f"ws_messages_{ts}.log")
        try:
            BinollaWebsocketClient._ws_log_file = open(
                BinollaWebsocketClient._ws_log_path, "a", encoding="utf-8")
            self._ws_log_write(f"# WebSocket session log — started at {datetime.now().isoformat()}\n"
                               f"# WSS URL: {WSS_URL}\n"
                               f"# Origin:  {ORIGIN_URL}\n"
                               f"# Token:   {(self.state.SSID or '')[:40]}...\n"
                               f"# Format:  DIR | LEN | TIME | RAW (or hex for binary)\n"
                               f"# DIR: ← = received from server, → = sent to server\n"
                               f"# ===========================================================\n")
            bn_logmsg(f"{Colors.CYAN}WS message log: {BinollaWebsocketClient._ws_log_path.absolute()}{Colors.RESET}")
        except Exception as e:
            logger.warning("Could not open WS log file: %s", e)

    @classmethod
    def _ws_log_write(cls, line: str) -> None:
        """يكتب سطراً في ملف سجل WebSocket (thread-safe بشكل بسيط)."""
        if cls._ws_log_file is None:
            return
        try:
            cls._ws_log_file.write(line)
            cls._ws_log_file.flush()
        except Exception:
            pass

    def _log_incoming(self, msg) -> None:
        """يسجل رسالة واردة من الخادم (في ملف السجل + على الـ console)."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(msg, (bytes, bytearray)):
            data = bytes(msg)
            # جرب JSON decode للـ binary packets
            try:
                decoded = data.decode("utf-8", errors="ignore")
                if decoded and decoded[0] in '[{':
                    self._ws_log_write(f"← BIN {len(data):6d} {ts} {decoded[:5000]}\n")
                    # اطبع على الـ console (مقتطع لمنع الفيض)
                    return
            except Exception:
                pass
            # وإلا، اعرض الـ hex أول 200 بايت
            hex_preview = data[:200].hex()
            self._ws_log_write(f"← BIN {len(data):6d} {ts} hex={hex_preview}\n")
            try:
                ascii_preview = data[:500].decode("utf-8", errors="replace")
                self._ws_log_write(f"         ascii={ascii_preview}\n")
            except Exception:
                pass
        else:
            text = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)
            preview = text if len(text) <= 5000 else text[:5000] + f"... [truncated, total={len(text)}]"
            self._ws_log_write(f"← TXT {len(text):6d} {ts} {preview}\n")

    def _log_outgoing(self, data) -> None:
        """يسجل رسالة صادرة من العميل (في ملف السجل + على الـ console)."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        if isinstance(data, (bytes, bytearray)):
            d = bytes(data)
            try:
                decoded = d.decode("utf-8", errors="ignore")
                if decoded and decoded[0] in '[{012345"':
                    self._ws_log_write(f"→ BIN {len(d):6d} {ts} {decoded[:5000]}\n")
                    return
            except Exception:
                pass
            hex_preview = d[:200].hex()
            self._ws_log_write(f"→ BIN {len(d):6d} {ts} hex={hex_preview}\n")
        else:
            text = str(data)
            preview = text if len(text) <= 5000 else text[:5000] + f"... [truncated, total={len(text)}]"
            self._ws_log_write(f"→ TXT {len(text):6d} {ts} {preview}\n")


    # ---- on_open: يُرسل بعد فتح قناة WebSocket -----
    def on_open(self, wss):
        logger.info("WebSocket connected to %s", WSS_URL)
        bn_logmsg(f"WebSocket channel opened to {WS_HOST}")
        self.state.check_websocket_if_connect = 1
        self.state.status = WebsocketStatus.CONNECTING
        # في EIO=4 ننتظر رسالة 0{...} (Engine.IO OPEN) قبل إرسال 40
        # (يحدث داخل _on_engineio_open). لا نرسل شيئاً هنا.

    # ---- on_message: قلب المعالج -----
    def on_message(self, wss, msg):
        # سجلّ الرسالة الواردة (text أو binary) في ملف السجل
        try:
            self._log_incoming(msg)
        except Exception:
            pass

        self.state.ssl_Mutual_exclusion = True
        try:
            if self.api is not None:
                self.api.last_message_at = time.time()

            # رسالة ثنائية (bytes) — قد تكون مُرفق لـ binary event سابق
            if isinstance(msg, (bytes, bytearray)):
                self._on_binary_frame(bytes(msg))
                self.state.ssl_Mutual_exclusion = False
                return

            msg_str = msg.decode("utf-8", errors="ignore") if isinstance(msg, bytes) else str(msg)

            # 1) PING من الخادم — نردّ بـ PONG فوراً
            if msg_str == "2":
                self._last_server_ping_at = time.time()
                try:
                    self.wss.send("3")
                except Exception:
                    pass
                self.state.ssl_Mutual_exclusion = False
                return

            # 2) PONG من الخادم (ردّ على ping أرسلناه)
            if msg_str == "3":
                self.state.ssl_Mutual_exclusion = False
                return

            # 3) Engine.IO OPEN: 0{"sid":...,"pingInterval":25000,...}
            if msg_str.startswith("0"):
                self._on_engineio_open(msg_str[1:])
                self.state.ssl_Mutual_exclusion = False
                return

            # 4) Socket.IO CONNECT_ACK: 40{"sid":"..."}
            if msg_str.startswith("40"):
                logger.info("Socket.IO namespace connected: %s", msg_str[2:] or "(no sid)")
                self.state.signal_ws_connected()
                self.state.status = WebsocketStatus.CONNECTED
                # أرسل authorization الآن
                self._send_authorization()
                self.state.ssl_Mutual_exclusion = False
                return

            # 5) Socket.IO DISCONNECT: 41
            if msg_str.startswith("41"):
                logger.warning("Socket.IO namespace disconnected by server.")
                self.state.check_websocket_if_connect = 0
                self.state.status = WebsocketStatus.DISCONNECTED
                self.state.signal_ws_closed()
                self.state.ssl_Mutual_exclusion = False
                return

            # 6) Binary event prefix: 45N-<json>
            if msg_str.startswith("45") and len(msg_str) >= 4 and msg_str[3] == '-':
                self._on_binary_event_header(msg_str)
                self.state.ssl_Mutual_exclusion = False
                return

            # 7) Socket.IO text EVENT: 42[event, data]
            if msg_str.startswith("42"):
                self._on_text_event(msg_str[2:])
                self.state.ssl_Mutual_exclusion = False
                return

            # أي شيء آخر (6 noop، إلخ) — نتجاهله
            logger.debug("Unhandled Engine.IO frame: %s", msg_str[:120])
        except Exception as e:
            logger.error("Unhandled error in on_message: %s", e)
            bn_log_exception("on_message", e)
        self.state.ssl_Mutual_exclusion = False

    # ---- 0{...}: تحديث إعدادات heartbeat ----
    def _on_engineio_open(self, payload: str) -> None:
        if not payload:
            return
        data = _safe_json_loads(payload)
        if not isinstance(data, dict):
            return
        # pingInterval / pingTimeout مقدّرة بالمللي ثانية
        pi = data.get("pingInterval")
        pt = data.get("pingTimeout")
        if isinstance(pi, (int, float)):
            self._ping_interval = float(pi) / 1000.0
        if isinstance(pt, (int, float)):
            self._ping_timeout = float(pt) / 1000.0
        sid = data.get("sid", "")
        logger.info("Engine.IO OPEN: sid=%s pingInterval=%.1fs pingTimeout=%.1fs",
                    sid, self._ping_interval, self._ping_timeout)
        bn_logmsg(f"Engine.IO session established (sid={sid[:8]}..., "
               f"ping={self._ping_interval:.0f}s)")
        # مهم في EIO=4: العميل يُرسل '40' (Socket.IO CONNECT) طلباً
        # للانضمام إلى namespace الافتراضي "/".
        # الخادم سيردّ بـ 40{"sid":"..."} (CONNECT_ACK) ثم نكمل المصادقة.
        try:
            self._log_outgoing("40")
            self.wss.send("40")
            logger.info("Sent Socket.IO CONNECT (40).")
        except Exception as e:
            logger.error("Failed to send 40 CONNECT: %s", e)

    # ---- 42[...]: حدث نصّي ----
    def _on_text_event(self, payload: str) -> None:
        arr = _safe_json_loads(payload)
        if not isinstance(arr, list) or not arr:
            return
        event_name = arr[0]
        args = arr[1:] if len(arr) > 1 else []

        # أحداث المصادقة
        if event_name == "authorization" and args:
            # قد يصل ردّ على auth إضافي (نادر)
            self._handle_authorization_response(args[0])
        elif event_name == "s_authorization":
            # تأكيد المصادقة من الخادم (بدون payload)
            logger.info("Authorization ACCEPTED by server.")
            bn_logmsg(f"{Colors.GREEN}Authorization accepted.{Colors.RESET}")
            self.state.check_accepted_connection = True
            self.state.check_rejected_connection = False
            self.state.auth_status = AuthStatus.AUTHENTICATED
            self.state.status = WebsocketStatus.CONNECTED
            self.state.signal_auth_accepted()
            # بعد التأكيد، نُشترك في كل القنوات
            self._send_post_auth_subscriptions()
        elif event_name == "authorization/reject":
            logger.warning("Authorization REJECTED by server.")
            bn_logmsg(f"{Colors.RED}Authorization rejected.{Colors.RESET}")
            self.state.check_rejected_connection = True
            self.state.auth_status = AuthStatus.FAILED
            self.state.signal_auth_rejected()
        else:
            # أي حدث نصّي آخر — مرّره إلى EventRegistry / المعالجات
            self._dispatch_event(event_name, args, binary_payload=None)

    # ---- 45N-<json>: رأس حدث ثنائي ----
    def _on_binary_event_header(self, msg_str: str) -> None:
        """نستقبل رأس 45N-<json>، ثم ننتظر N إطار ثنائي بعد ذلك."""
        try:
            # استخراج العدد N والـ json
            # الصيغة: '4' + '5' + '<digit>' + '-' + <json>
            n_attachments = int(msg_str[2])
            json_text = msg_str[4:]
            arr = _safe_json_loads(json_text)
            if not isinstance(arr, list):
                logger.warning("Malformed binary event header: %s", msg_str[:120])
                return
            if n_attachments <= 0:
                # بدون مُرفقات — عالجه كأنه حدث نصّي
                self._dispatch_event(arr[0], arr[1:], binary_payload=None)
                return
            # ضعه في الطابور وانتظر الإطارات الثنائية
            self._binary_packet_queue.append({
                "parts": arr,
                "expected": n_attachments,
                "received": 0,
                "buffers": [],
            })
        except Exception as e:
            logger.error("Error parsing binary header: %s — %s", e, msg_str[:120])

    # ---- إطار ثنائي يصل بعد رأس 45N-... ----
    def _on_binary_frame(self, data: bytes) -> None:
        if not self._binary_packet_queue:
            logger.debug("Stray binary frame (%d bytes) — no pending header.", len(data))
            return
        # آخر طلب في الطابور (LIFO) — يتوافق مع سلوك Socket.IO v4
        pending = self._binary_packet_queue[-1]
        pending["buffers"].append(data)
        pending["received"] += 1
        if pending["received"] >= pending["expected"]:
            # اكتمل — انزع من الطابور وعالجه
            self._binary_packet_queue.pop()
            self._reassemble_and_dispatch(pending)

    # ---- إعادة تجميع الـ placeholders في الـ JSON ----
    def _reassemble_and_dispatch(self, pending: Dict) -> None:
        """يأخذ الـ JSON الأصلي (مع _placeholder:true,num:N) ويستبدلها بالمُرفقات الثنائية."""
        try:
            parts = pending["parts"]
            buffers = pending["buffers"]

            # الخطاف البطيء: ابحث عن كل _placeholder في الـ JSON واستبدله
            def _walk(obj: Any) -> Any:
                if isinstance(obj, dict):
                    if obj.get("_placeholder") is True and "num" in obj:
                        n = int(obj["num"])
                        if 0 <= n < len(buffers):
                            return buffers[n]
                        return None
                    return {k: _walk(v) for k, v in obj.items()}
                if isinstance(obj, list):
                    return [_walk(x) for x in obj]
                return obj

            parts = [_walk(p) for p in parts]

            event_name = parts[0] if parts else ""
            args = parts[1:] if len(parts) > 1 else []
            self._dispatch_event(event_name, args, binary_payload=None)
        except Exception as e:
            logger.error("Error reassembling binary packet: %s", e)

    # ---- توزيع الحدث على المعالجات / EventRegistry ----
    def _dispatch_event(self, event_name: str, args: List[Any],
                       binary_payload: Optional[bytes]) -> None:
        # حاول فك الـ bytes كـ JSON إن أمكن
        decoded_args = []
        for a in args:
            if isinstance(a, (bytes, bytearray)):
                # جرب JSON أولاً (الأكثر شيوعاً في Binolla)
                as_json = _safe_json_loads(a)
                if as_json is not None:
                    decoded_args.append(as_json)
                else:
                    # إذا فشل JSON، احتفظ بالـ bytes الخام
                    decoded_args.append(bytes(a))
            else:
                decoded_args.append(a)

        # طبّق القناة
        try:
            self.api.event_data[event_name] = decoded_args
        except Exception:
            pass

        # استدعِ المعالج المخصص إن وُجد
        try:
            handler = self.api.event_handlers.get(event_name)
            if handler:
                handler(*decoded_args)
        except Exception as e:
            logger.error("Event handler error for '%s': %s", event_name, e)

        # ارفع الـ async events المقابلة
        try:
            loop = self.api._async_loop
            if loop and loop.is_running():
                asyncio.run_coroutine_threadsafe(
                    self.api.event_registry.set_event(event_name, decoded_args), loop)
        except Exception as e:
            logger.debug("Could not signal event '%s': %s", event_name, e)

        # تسجيل آخر رسالة من نوع quotes (live prices)
        if event_name == "s_quotes/list" and decoded_args:
            try:
                self.api.realtime_quotes = decoded_args[0]
            except Exception:
                pass

        # آخر شمعة لحظية من history/last
        if event_name == "s_history/last" and decoded_args:
            try:
                self.api.history_last = decoded_args[0]
            except Exception:
                pass

        # جلب الشموع التاريخية عبر history/region
        # الـ payload الثنائي يجب أن يحتوي على `index` لمطابقة الطلب.
        if event_name == "s_history/region" and decoded_args:
            try:
                payload = decoded_args[0]
                index = None
                # ابحث عن `index` في بنى متعددة محتملة:
                # - dict: {"index":..., "candles":[...]}
                # - list of dicts: [{"index":..., "candles":[...]}]
                # - dict تحت "data": {"data":{"index":..., "candles":[...]}}
                if isinstance(payload, dict):
                    index = payload.get("index")
                    if index is None and isinstance(payload.get("data"), dict):
                        index = payload["data"].get("index")
                elif isinstance(payload, list) and payload and isinstance(payload[0], dict):
                    index = payload[0].get("index")
                # خزّن الـ payload تحت الـ index المُستخرج
                if index is not None:
                    self.api.history_regions[index] = payload
                    # ارفع الـ event المُطابق
                    loop = self.api._async_loop
                    if loop and loop.is_running():
                        asyncio.run_coroutine_threadsafe(
                            self.api.event_registry.set_event(
                                f's_history/region_{index}', payload),
                            loop)
                    # سكّت الـ logging التفصيلي (نُبقي فقط الرسائل البسيطة مثل qx__1.py)
                    logger.debug("s_history/region received (index=%s, payload_size=%d chars)",
                                index, len(str(payload)))
                else:
                    logger.warning("s_history/region: no index field found in payload")
            except Exception as e:
                logger.error("Error handling s_history/region: %s", e)

        # الأرصدة
        if event_name == "s_balances/list" and decoded_args:
            try:
                self.api.balances = decoded_args[0]
            except Exception:
                pass

        # قائمة الأصول
        if event_name == "s_assets/list" and decoded_args:
            try:
                self.api.assets_list = decoded_args[0]
            except Exception:
                pass

        # الطلبات المفتوحة
        if event_name == "s_orders/opened/list" and decoded_args:
            try:
                self.api.opened_orders = decoded_args[0]
            except Exception:
                pass

        # الطلبات المغلقة
        if event_name == "s_orders/closed/list" and decoded_args:
            try:
                self.api.closed_orders = decoded_args[0]
            except Exception:
                pass

        # الإعدادات
        if event_name == "s_settings/list" and decoded_args:
            try:
                self.api.settings = decoded_args[0]
            except Exception:
                pass

        # ===== sentiment / payout (نسبة الدفع) =====
        # s_asset/sentiment: {"asset":"AUDCHF_otc","sentiment":17}
        # هذا الحدث يحمل نسبة الدفع (payout %) لكل أصل
        if event_name == "s_asset/sentiment" and decoded_args:
            try:
                payload = decoded_args[0]
                if isinstance(payload, list) and payload:
                    for item in payload:
                        if isinstance(item, dict) and "asset" in item:
                            self.api.assets_sentiment[item["asset"]] = item
                elif isinstance(payload, dict) and "asset" in payload:
                    self.api.assets_sentiment[payload["asset"]] = payload
            except Exception as e:
                logger.debug("Error storing s_asset/sentiment: %s", e)

        # ===== signals (إشارات الدفع لفريمات زمنية مختلفة) =====
        if event_name == "s_signals/asset/change" and decoded_args:
            try:
                payload = decoded_args[0]
                if isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict) and "asset" in item:
                            asset_name = item["asset"]
                            tf = item.get("timeframe", 0)
                            self.api.assets_signals.setdefault(asset_name, {})[tf] = item
                elif isinstance(payload, dict) and "asset" in payload:
                    asset_name = payload["asset"]
                    tf = payload.get("timeframe", 0)
                    self.api.assets_signals.setdefault(asset_name, {})[tf] = payload
            except Exception as e:
                logger.debug("Error storing s_signals/asset/change: %s", e)

        # ===== quotes list (الأسعار اللحظية) =====
        # يمكن أن يصل كـ "s_quotes/list" مع list of {asset, price, ...}
        if event_name == "s_quotes/list" and decoded_args:
            try:
                payload = decoded_args[0]
                if isinstance(payload, list):
                    for item in payload:
                        if isinstance(item, dict) and "asset" in item:
                            self.api.assets_quotes[item["asset"]] = item
                elif isinstance(payload, dict) and "asset" in payload:
                    self.api.assets_quotes[payload["asset"]] = payload
            except Exception as e:
                logger.debug("Error storing s_quotes/list: %s", e)

    # ---- إرسال الـ authorization بعد الـ connect ----
    def _send_authorization(self) -> None:
        token = self.state.SSID or self.api.token
        if not token:
            bn_logmsg(f"{Colors.RED}No JWT token available — cannot authorize.{Colors.RESET}")
            self.state.signal_auth_rejected()
            return
        payload = {
            "token": token,
            "uaid": 0,
            "userAccountType": self.state.userAccountType,
        }
        data = '42["authorization",' + json.dumps(payload, separators=(",", ":")) + ']'
        try:
            self._log_outgoing(data)
            self.wss.send(data)
            logger.info("Authorization sent (token=%s...).", token[:24])
            bn_logmsg("Sent authorization frame to Binolla server...")
            self.state.auth_status = AuthStatus.PENDING
        except Exception as e:
            logger.error("Failed to send authorization: %s", e)
            self.state.signal_auth_rejected()

    # ---- اشتراك ما بعد المصادقة ----
    def _send_post_auth_subscriptions(self) -> None:
        """يرسل الطلبات الأولية بعد تأكيد المصادقة (يطابق الترتيب المُلتقط بدقة).

        ملاحظة هامة: بعد `s_authorization`، الخادم يُرسل تلقائياً 3 binary packets:
          - s_assets/list   (قائمة الأصول)
          - s_settings/list (الإعدادات)
          - s_balances/list (الأرصدة)
        ثم العميل يُرسل فقط الـ 8 طلبات التالية:
          1) orders/opened/list
          2) orders/closed/list
          3) assets/list
          4) alert/list
          5) alert/closed/list
          6) indicator/list
          7) drawing/load
          8) asset/list/change  ← هذا الطلب يُفعّل تدفقات s_history/last و s_quotes/list
        الـ server يستجيب لكل طلب بـ binary packet مطابق (s_<name>).
        """
        try:
            subscriptions = [
                '42["orders/opened/list"]',
                '42["orders/closed/list"]',
                '42["assets/list"]',
                '42["alert/list"]',
                '42["alert/closed/list"]',
                '42["indicator/list"]',
                '42["drawing/load"]',
            ]
            for msg in subscriptions:
                self._log_outgoing(msg)
                self.wss.send(msg)
                # مهلة صغيرة جداً بين الطلبات (50ms) لتجنّب الـ rate-limiting
                time.sleep(0.05)

            # 2) تغيير الأصل الافتراضي — يُفعّل s_history/last و s_quotes/list
            asset = self.api.current_asset or "EURUSD_otc"
            period = self.api.current_period or 1
            change_payload = [{"asset": asset, "period": period}]
            data = '42["asset/list/change",' + json.dumps(change_payload,
                                                          separators=(",", ":")) + ']'
            self._log_outgoing(data)
            self.wss.send(data)

            logger.info("Post-auth subscriptions sent (asset=%s, period=%s).", asset, period)
        except Exception as e:
            logger.error("Error sending post-auth subscriptions: %s", e)

    # ---- on_error / on_close ----
    def on_error(self, wss, error):
        logger.error("WebSocket error: %s", error)
        bn_log_exception("websocket.on_error", error if isinstance(error, BaseException)
                      else RuntimeError(str(error)))
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        self.state.signal_ws_error()

    def on_close(self, wss, close_status_code, close_msg):
        logger.info("WebSocket closed: code=%s msg=%s", close_status_code, close_msg)
        bn_logmsg(f"WebSocket closed (code={close_status_code}).")
        self.state.check_websocket_if_connect = 0
        self.state.status = WebsocketStatus.DISCONNECTED
        self.state.check_accepted_connection = False
        self.state.signal_ws_closed()

    def on_ping(self, wss, ping_msg): pass
    def on_pong(self, wss, pong_msg): pass


# ==============================================================================
# SECTION 6: EVENT REGISTRY (async wait-for-event)
# ==============================================================================
class EventRegistry:
    """تسجيل أحداث async — كل event_name له Event + data."""

    def __init__(self):
        self._events: Dict[str, asyncio.Event] = {}
        self._data: Dict[str, Any] = {}
        self._lock = asyncio.Lock()

    async def get_event(self, key: str) -> asyncio.Event:
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            return self._events[key]

    async def set_event(self, key: str, data: Any = None):
        async with self._lock:
            if key not in self._events:
                self._events[key] = asyncio.Event()
            self._data[key] = data
            self._events[key].set()

    async def wait_event(self, key: str, timeout: float = 30.0) -> Any:
        event = await self.get_event(key)
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            return self._data.get(key)
        except asyncio.TimeoutError:
            return None

    async def clear_event(self, key: str):
        async with self._lock:
            if key in self._events:
                self._events[key].clear()
            if key in self._data:
                del self._data[key]


# ==============================================================================
# SECTION 7: BINOLLA API CORE
# ==============================================================================
class BinollaAPI:
    """واجهة برمجية لمنصة Binolla — تتصل، تصادق، وتُرسل الطلبات."""

    def __init__(self, token: str = "", user_data_dir: str = ".",
                 is_demo: bool = True, proxies: Optional[str] = None):
        self.token = token
        self.state = ConnectionState()
        self.state.userAccountType = 1 if is_demo else 0
        self.is_demo = is_demo
        self.user_data_dir = user_data_dir
        self.proxies = proxies
        self.session_data: Dict[str, Any] = {"user_agent": USER_AGENT, "cookies": ""}

        # WebSocket
        self.websocket_thread: Optional[threading.Thread] = None
        self.websocket_client: Optional[BinollaWebsocketClient] = None
        self.last_message_at: float = time.time()

        # الحالة الحالية للأصل/الفريم
        self.current_asset: Optional[str] = None
        self.current_period: Optional[int] = None

        # أحدث بيانات مُلتقطة
        self.assets_list: Any = None
        self.balances: Any = None
        self.settings: Any = None
        self.opened_orders: Any = None
        self.closed_orders: Any = None
        self.history_last: Any = None
        self.history_regions: Dict[int, Any] = {}  # {index: payload} — لجلب الشموع المتوازي
        self.realtime_quotes: Any = None

        # ===== بيانات الأصول المُجمّعة =====
        # assets_sentiment: {asset_name: {"asset":..., "sentiment":17, ...}}
        # sentiment = نسبة الدفع (payout %) لكل أصل
        self.assets_sentiment: Dict[str, Any] = {}
        # assets_signals: {asset_name: {timeframe: signal_dict}}
        # signals = إشارات الدفع لفريمات زمنية مختلفة (M1, M5, M15)
        self.assets_signals: Dict[str, Dict[int, Any]] = {}
        # assets_quotes: {asset_name: {"asset":..., "price":..., "time":...}}
        # quotes = السعر اللحظي لكل أصل
        self.assets_quotes: Dict[str, Any] = {}

        # الأصل المُتابَع حالياً (للاستعادة بعد reconnect)
        self.watch_asset: Optional[str] = None

        # Event Registry
        self.event_registry = EventRegistry()
        self.event_data: Dict[str, Any] = {}
        self.event_handlers: Dict[str, Callable] = {}

        self._async_loop: Optional[asyncio.AbstractEventLoop] = None

    # ---- إعداد التوكن (لو مُرر بعد الإنشا) ----
    def set_token(self, token: str) -> None:
        self.token = token
        self.state.SSID = token

    def register_handler(self, event_name: str, handler: Callable) -> None:
        """يُسجّل معالجاً مخصصاً لحدث نصّي أو ثنائي محدد."""
        self.event_handlers[event_name] = handler

    # ---- إرسال طلب WebSocket عام ----
    def send_websocket_request(self, data: str, no_force_send: bool = True) -> None:
        if no_force_send:
            deadline = time.time() + 5.0
            while (self.state.ssl_Mutual_exclusion or self.state.ssl_Mutual_exclusion_write):
                if time.time() > deadline:
                    break
                time.sleep(0.001)
        self.state.ssl_Mutual_exclusion_write = True
        try:
            if self.websocket_client and self.websocket_client.wss:
                # سجلّ الرسالة الصادرة قبل الإرسال
                try:
                    self.websocket_client._log_outgoing(data)
                except Exception:
                    pass
                self.websocket_client.wss.send(data)
        finally:
            self.state.ssl_Mutual_exclusion_write = False

    # ---- بدء الاتصال WebSocket ----
    async def start_websocket(self, timeout: float = 15.0) -> Tuple[bool, str]:
        self.state.check_websocket_if_connect = None
        self.state.check_websocket_if_error = False
        self.state.websocket_error_reason = None
        self.state.init_events()
        self.state.reset_events()
        try:
            self.state._loop = asyncio.get_running_loop()
            self._async_loop = self.state._loop
        except RuntimeError:
            self.state._loop = None
            self._async_loop = None

        if not self.token:
            return False, "No JWT token provided."

        self.state.SSID = self.token
        self.websocket_client = BinollaWebsocketClient(self)

        payload = {
            "suppress_origin": True,
            # في EIO=4 لا نُفعّل WS-level ping — الخادم يُرسل Engine.IO PING ("2")
            # كل 25 ثانية، ونردّ بـ "3" داخل on_message. لو فعّلنا ping_interval هنا،
            # مكتبة websocket-client ستُرسل WS PING frames (مستوى RFC 6455) وقد
            # تُربك خادم Socket.IO. نُبقي ping_interval=0 (معطّل) و ping_timeout=30
            # (قيمة افتراضية — المكتبة تتطلبها >0 حتى لو كان ping_interval=0).
            "ping_interval": 0,
            "ping_timeout": 30,
            "origin": ORIGIN_URL,
            "host": WS_HOST,
            "sslopt": {
                "check_hostname": True,
                "cert_reqs": ssl.CERT_REQUIRED,
                "ca_certs": cacert,
                "context": ssl_context,
            },
        }
        # دعم البروكسي
        if self.proxies:
            try:
                from urllib.parse import urlparse
                p = urlparse(self.proxies if isinstance(self.proxies, str) else self.proxies.get("http", ""))
                if p.hostname and p.port:
                    payload["http_proxy_host"] = p.hostname
                    payload["http_proxy_port"] = p.port
                    if p.scheme.startswith("socks"):
                        payload["http_proxy_auth_timeout"] = 30
            except Exception:
                pass

        self.websocket_thread = threading.Thread(
            target=self.websocket_client.wss.run_forever, kwargs=payload)
        self.websocket_thread.daemon = True
        self.websocket_thread.start()

        try:
            idx = await wait_for_first_event(
                self.state.ws_connected_event,
                self.state.auth_rejected_event,
                self.state.ws_error_event,
                self.state.ws_closed_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False, "Timeout waiting for websocket open / namespace connect"

        if idx == 0:
            return True, "Websocket connected successfully."
        elif idx == 1:
            self.state.SSID = None
            return False, "Websocket token rejected."
        elif idx == 2:
            return False, self.state.websocket_error_reason or "Websocket error"
        elif idx == 3:
            return False, "Websocket connection closed."
        return False, "Unknown websocket state"

    # ---- انتظار تأكيد المصادقة ----
    async def wait_for_authorization(self, timeout: float = 15.0) -> bool:
        if not self.state.auth_accepted_event:
            self.state.init_events()
        self.state.auth_accepted_event.clear()
        self.state.auth_rejected_event.clear()
        try:
            idx = await wait_for_first_event(
                self.state.auth_accepted_event,
                self.state.auth_rejected_event,
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            return False
        return idx == 0

    # ---- الاتصال الكامل (websocket + auth) ----
    async def connect(self) -> Tuple[bool, str]:
        self.state.ssl_Mutual_exclusion = False
        self.state.ssl_Mutual_exclusion_write = False
        check_websocket, websocket_reason = await self.start_websocket()
        if not check_websocket:
            return check_websocket, websocket_reason
        # بعد ws_connected، يُرسل العميل authorization تلقائياً داخل on_message
        check_auth = await self.wait_for_authorization(timeout=15.0)
        if not check_auth:
            return False, "Authorization failed or timed out."
        return True, "Connected and authorized."

    # ---- إغلاق ----
    async def close(self) -> bool:
        if self.websocket_client and self.websocket_client.wss:
            try:
                self.websocket_client.wss.close()
            except Exception:
                pass
            await asyncio.sleep(0.5)
        if self.websocket_thread and self.websocket_thread.is_alive():
            self.websocket_thread.join(timeout=5)
        return True

    # ===================================================================
    # دوال Binolla المُيسّرة (薄 core API)
    # ===================================================================

    def change_asset(self, asset: str, period: int) -> None:
        """يُبدّل الأصل والفريم. مثال: change_asset('EURUSD_otc', 1)"""
        self.current_asset = asset
        self.current_period = period
        payload = [{"asset": asset, "period": period}]
        data = '42["asset/list/change",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)

    def restore_subscriptions(self) -> None:
        """يُعيد إرسال كل الاشتراكات بعد إعادة اتصال WebSocket.

        يُستدعى تلقائياً بعد نجاح الـ watchdog reconnect. يعيد:
        1) asset/list/change للأصل المُتابَع (إن وُجد) لتفعيل تدفق quotes
        2) asset/sentiment/subscribe لجلب نسبة الدفع
        3) s_asset/sentiment/subscribe للاشتراك العام
        4) quotes/list لطلب الأسعار فوراً
        5) assets/list لتحديث قائمة الأصول
        """
        try:
            # إن وُجد أصل مُتابَع، أعد تفعيل تدفق quotes له
            asset = self.watch_asset or self.current_asset
            if asset:
                period = self.current_period or 60
                self.change_asset(asset, period)
                time.sleep(0.05)
                # اشترك في sentiment خاص بالأصل
                self.subscribe_asset_sentiment(asset)
                time.sleep(0.05)
            # اشترك في sentiment العام
            self.subscribe_global_sentiment()
            time.sleep(0.05)
            # اطلب quotes و assets فوراً
            self.subscribe_quotes()
            time.sleep(0.05)
            self.fetch_assets()
            logger.info("Subscriptions restored after reconnect (asset=%s).",
                        asset or "none")
        except Exception as e:
            logger.error("Error restoring subscriptions: %s", e)

    def subscribe_quotes(self) -> None:
        """يشترك في بث الاقتباسات اللحظية (s_quotes/list)."""
        self.send_websocket_request('42["quotes/list"]')

    # ===== دوال sentiment / signals / payout =====
    def subscribe_global_sentiment(self) -> None:
        """يشترك في بث sentiment لكل الأصول (s_asset/sentiment).

        بعد الاشتراك، يصل حدث:
            ["s_asset/sentiment", {"asset":"AUDCHF_otc","sentiment":17}]
        حيث sentiment = نسبة الدفع (payout %) لكل أصل.
        """
        self.send_websocket_request('42["s_asset/sentiment/subscribe"]')

    def subscribe_asset_sentiment(self, asset: str) -> None:
        """يشترك في sentiment (نسبة الدفع) لأصل محدد.

        مرسل من المتصفح: ["asset/sentiment/subscribe", "AUDCHF_otc"]
        الاستجابة: ["s_asset/sentiment", {"asset":"AUDCHF_otc","sentiment":17}]
        """
        data = '42["asset/sentiment/subscribe",' + json.dumps(asset, separators=(",", ":")) + ']'
        self.send_websocket_request(data)

    def subscribe_asset_signals(self, asset: str,
                                  timeframes: Optional[List[int]] = None) -> None:
        """يشترك في إشارات الأصل لفريمات زمنية متعددة.

        مرسل من المتصفح (مثال):
          ["s_signals/asset/subscribe",[
              {"asset":"AUDCHF_otc","timeframe":120,"cmd":1,"expire":1791371760},
              {"asset":"AUDCHF_otc","timeframe":600,"cmd":1,"expire":1791372000},
              {"asset":"AUDCHF_otc","timeframe":900,"cmd":1,"expire":1791371700}
          ]]

        الاستجابة:
          ["s_signals/asset/change", [{"asset":"AUDCHF_otc","timeframe":900,"cmd":1,"expire":...}]]
        """
        if timeframes is None:
            timeframes = [60, 120, 300, 600, 900]
        now = int(time.time())
        items = []
        for tf in timeframes:
            items.append({
                "asset": asset,
                "timeframe": int(tf),
                "cmd": 1,
                "expire": now + int(tf),
            })
        data = '42["s_signals/asset/subscribe",' + json.dumps(items, separators=(",", ":")) + ']'
        self.send_websocket_request(data)

    def fetch_assets(self) -> None:
        self.send_websocket_request('42["assets/list"]')

    def fetch_balances(self) -> None:
        self.send_websocket_request('42["balances/list"]')

    def fetch_settings(self) -> None:
        self.send_websocket_request('42["settings/list"]')

    def fetch_orders_opened(self) -> None:
        self.send_websocket_request('42["orders/opened/list"]')

    def fetch_orders_closed(self) -> None:
        self.send_websocket_request('42["orders/closed/list"]')

    def fetch_history_last(self) -> None:
        self.send_websocket_request('42["history/last"]')

    def fetch_history_region(self, asset: str, time_sec: int, index: Optional[int] = None,
                              offset: int = 1000, period: int = 1) -> int:
        """يرسل طلب جلب شموع تاريخية من منطقة زمنية محددة.

        الـ endpoint: `history/region`
        الـ response: `s_history/region` (binary packet يحتوي على ~offset شمعة JSON)

        المعاملات:
          asset    : اسم الأصل (مثل 'EURUSD_otc')
          time_sec : Unix timestamp (seconds) لبداية المنطقة الزمنية
          index    : مُعرّف فريد للطلب (إن لم يُمرّر، يُولّد تلقائياً)
          offset   : عدد الشموع لكل batch (افتراضي 1000)
          period    : الفريم بالدقائق (1 = M1, 5 = M5, 15 = M15, 30 = M30, 60 = H1)

        يُعيد: الـ `index` المُستخدم (لمطابقة الاستجابة عبر event
        `s_history/region_<index>`).
        """
        if index is None:
            index = next(_request_counter)
        payload = {
            "asset": asset,
            "index": index,
            "time": int(time_sec),
            "offset": int(offset),
            "period": int(period),
        }
        data = '42["history/region",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)
        logger.debug("history/region sent: asset=%s time=%d offset=%d period=%d index=%d",
                    asset, time_sec, offset, period, index)
        return index

    def fetch_alerts(self) -> None:
        self.send_websocket_request('42["alert/list"]')

    def fetch_alerts_closed(self) -> None:
        self.send_websocket_request('42["alert/closed/list"]')

    def fetch_indicators(self) -> None:
        self.send_websocket_request('42["indicator/list"]')

    def load_drawings(self) -> None:
        self.send_websocket_request('42["drawing/load"]')

    # ---- وضع صفقة (binary option) ----
    def place_order(self, asset: str, amount: float, direction: str,
                    expiration: int, account_type: int = 1) -> None:
        """يفتح صفقة على منصة Binolla.

        المعاملات:
          asset        : اسم الأصل، مثلاً 'EURUSD_otc'
          amount       : المبلغ بالدولار (أو عملة الحساب)
          direction    : 'call' (صعود) أو 'put' (هبوط)
          expiration   : مدة الصفقة بالثواني (60, 120, 180, 300, 600)
          account_type : 1 = demo, 0 = real
        """
        direction = direction.lower()
        if direction not in ("call", "put"):
            raise ValueError(f"direction must be 'call' or 'put', got: {direction}")
        payload = {
            "asset": asset,
            "amount": float(amount),
            "direction": direction,
            "expiration": int(expiration),
            "userAccountType": account_type,
        }
        data = '42["orders/open",' + json.dumps(payload, separators=(",", ":")) + ']'
        self.send_websocket_request(data)
        logger.info("Order sent: %s %s %.2f exp=%ds", asset, direction, amount, expiration)

    # ---- جلب قائمة الأصول مع انتظار ----
    async def get_assets_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_assets/list")
        self.fetch_assets()
        return await self.event_registry.wait_event("s_assets/list", timeout=timeout)

    async def get_balances_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_balances/list")
        self.fetch_balances()
        return await self.event_registry.wait_event("s_balances/list", timeout=timeout)

    async def get_settings_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_settings/list")
        self.fetch_settings()
        return await self.event_registry.wait_event("s_settings/list", timeout=timeout)

    async def get_orders_opened_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_orders/opened/list")
        self.fetch_orders_opened()
        return await self.event_registry.wait_event("s_orders/opened/list", timeout=timeout)

    async def get_orders_closed_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_orders/closed/list")
        self.fetch_orders_closed()
        return await self.event_registry.wait_event("s_orders/closed/list", timeout=timeout)

    async def get_history_last_async(self, timeout: float = 10.0) -> Any:
        await self.event_registry.clear_event("s_history/last")
        self.fetch_history_last()
        return await self.event_registry.wait_event("s_history/last", timeout=timeout)


# ==============================================================================
# SECTION 8: BINOLLA STABLE CLIENT (واجهة مستخدم + جلب الشموع)
# ==============================================================================
class Binolla:
    """واجهة عالية المستوى للاستخدام التفاعلي."""

    def __init__(self, token: str = "", is_demo: bool = True,
                 user_data_dir: str = ".", proxies: Optional[str] = None):
        self.token = token
        self.is_demo = is_demo
        self.user_data_dir = user_data_dir
        self.proxies = proxies
        self.api: Optional[BinollaAPI] = None

    async def connect(self) -> Tuple[bool, str]:
        """يتصل بـ Binolla. يُعيد استخدام كائن API الموجود إن وُجد للحفاظ
        على الحالة (watch_asset, current_asset, assets_quotes, إلخ) عبر إعادة
        الاتصال."""
        if self.api is None:
            # أول اتصال: أنشئ كائن API جديد
            self.api = BinollaAPI(
                token=self.token,
                is_demo=self.is_demo,
                user_data_dir=self.user_data_dir,
                proxies=self.proxies,
            )
        else:
            # إعادة اتصال: حدّث التوكن فقط، احتفظ بكل الحالة (watch_asset, etc.)
            self.api.token = self.token
            self.api.state.SSID = self.token
            # أعد تهيئة events للجولة الجديدة
            self.api.state.init_events()
            self.api.state.reset_events()
        self.api._async_loop = asyncio.get_running_loop()
        return await self.api.connect()

    async def change_account(self, balance_mode: str) -> None:
        """يُبدّل بين الحساب الحقيقي والتجريبي."""
        is_demo = balance_mode.upper() != "REAL"
        self.is_demo = is_demo
        if self.api:
            self.api.state.userAccountType = 1 if is_demo else 0
            payload = {"userAccountType": self.api.state.userAccountType}
            data = '42["account/change",' + json.dumps(payload, separators=(",", ":")) + ']'
            self.api.send_websocket_request(data)

    async def start_candles_stream(self, asset: str = "EURUSD_otc",
                                    period: int = 1) -> None:
        if self.api:
            self.api.current_asset = asset
            self.api.current_period = period
            self.api.change_asset(asset, period)
            self.api.subscribe_quotes()

    async def fetch_candles(self, asset: str, days: int, timeframe_min: int,
                            timeout: int = 30, max_workers: int = 5,
                            progress_callback: Optional[Callable] = None) -> List[Dict]:
        """يجلب الشموع التاريخية من Binolla عبر `history/region` بنفس طريقة qx__1.py.

        آلية العمل:
        - عدد الثواني المطلوب = days * 86400
        - كل batch = `offset` شموع (افتراضي 1000) = offset * period * 60 ثانية
        - نقسّم النطاق الزمني على max_workers (5 افتراضياً) لجلب متوازٍ
        - كل worker يُرسل طلبات history/region بالتسلسل مع انتظار s_history/region_<index>
        - ندمج كل الشموع المستلمة من كل العمال، مع تجنّب التكرار (نفس الـ time)
        - نُعيد القائمة مرتّبة حسب time
        """
        if not self.api:
            return []
        # فعّل تدفق البيانات للأصل المطلوب
        await self.start_candles_stream(asset, timeframe_min)
        await asyncio.sleep(0.3)

        period_sec = timeframe_min * 60            # ثانية لكل شمعة
        # offset = مدة البيانات المطلوبة بالثواني (Binolla يُرجع ~offset ثانية من الـ ticks)
        # المتصفح يستخدم offset=1000. نستخدم نفس القيمة لتحسين الإنتاجية.
        offset_sec = 1000
        chunk_seconds = offset_sec                  # ثانية لكل batch (= 1000 ثانية ≈ 16.7 دقيقة)
        amount_of_seconds = days * 86400            # ثانية إجمالية مطلوبة

        all_candles: Dict[int, Dict] = {}          # {time: candle} — للدمج دون تكرار
        current_time = int(time.time())
        target_start_time = current_time - amount_of_seconds
        block_size = amount_of_seconds // max_workers
        semaphore = asyncio.Semaphore(max_workers)

        async def worker(start_t: int, end_t: int, worker_id: int) -> List[Dict]:
            worker_candles: Dict[int, Dict] = {}
            async with semaphore:
                oldest_t = start_t
                consecutive_failures = 0
                while oldest_t > end_t:
                    # تحقق من الاتصال قبل كل batch
                    if not self.api or not getattr(self.api.state, 'check_accepted_connection', False):
                        break
                    # ولّد index فريد وأرسل الطلب
                    index = self.api.fetch_history_region(
                        asset=asset, time_sec=oldest_t, period=timeframe_min,
                        offset=offset_sec)
                    # انتظر الاستجابة (s_history/region_<index> يُطلق من _dispatch_event)
                    result = await self.api.event_registry.wait_event(
                        f's_history/region_{index}', timeout=timeout)
                    if not result:
                        # لا استجابة — حرّك نافذة الوقت للوراء
                        oldest_t -= chunk_seconds
                        consecutive_failures += 1
                        if consecutive_failures >= 3:
                            logger.warning("Worker %d: 3 consecutive failures — aborting.",
                                           worker_id)
                            break
                        await asyncio.sleep(FETCH_BATCH_DELAY * 2)
                        continue
                    consecutive_failures = 0
                    # حوّل الـ payload إلى شموع
                    new_batch = self._parse_history(result, period_min=timeframe_min)
                    if not new_batch:
                        oldest_t -= chunk_seconds
                        continue
                    batch_times = []
                    for c in new_batch:
                        ts = c.get('time', 0)
                        if end_t <= ts <= start_t:
                            worker_candles[ts] = c
                            batch_times.append(ts)
                    if not batch_times:
                        # الـ response خارج نطاق الـ worker — تحرّك للوراء
                        oldest_t -= chunk_seconds
                        continue
                    # تحديث أقدم وقت للجلب التالي
                    new_oldest = min(batch_times)
                    if progress_callback:
                        progress_callback(start_t - new_oldest, start_t - end_t,
                                          len(worker_candles), f"Worker-{worker_id}")
                    oldest_t = new_oldest if new_oldest < oldest_t else oldest_t - chunk_seconds
                    await asyncio.sleep(FETCH_BATCH_DELAY)
            return list(worker_candles.values())

        # شغّل max_workers عمال بالتوازي
        tasks = []
        for i in range(max_workers):
            s = current_time - (i * block_size)
            e = max(target_start_time, s - block_size)
            tasks.append(worker(s, e, i))
        results = await asyncio.gather(*tasks)
        # ادمج كل النتائج
        for batch in results:
            for c in batch:
                all_candles[c['time']] = c
        # رتّب حسب time
        return sorted(all_candles.values(), key=lambda x: x['time'])

    def _parse_history(self, payload: Any, period_min: int = 1) -> List[Dict]:
        """يُحوّل payload الـ s_history/region إلى قائمة شموع بصيغة OHLC.

        Binolla يُرسل **ticks** وليس OHLC candles. كل tick = [timestamp, price, direction].
        لذا نجمع الـ ticks إلى شموع حسب الفريم المطلوب:
          - period_min=1  → شمعة لكل دقيقة (60 ثانية)
          - period_min=5  → شمعة لكل 5 دقائق (300 ثانية)
          - period_min=15 → شمعة لكل 15 دقيقة (900 ثانية)
          ... إلخ

        صيغ الـ payload المدعومة:
          1) {"asset":..., "period":..., "history":[[ts, price, dir], ...]}  ← Binolla tick format
          2) {"index":..., "candles":[[time, open, close, high, low, vol], ...]}  ← Quotex-style
          3) {"index":..., "candles":[{"time","open",...}, ...]}
          4) [[time, open, close, high, low, vol], ...]
        """
        if not payload:
            return []

        # استخرج candles/ticks من payload
        ticks_or_candles = None
        period_from_payload = None
        if isinstance(payload, dict):
            ticks_or_candles = (payload.get("history") or payload.get("candles")
                                or payload.get("data") or payload.get("list"))
            period_from_payload = payload.get("period")
            if ticks_or_candles is None and isinstance(payload.get("data"), dict):
                ticks_or_candles = (payload["data"].get("candles")
                                     or payload["data"].get("history") or [])
        elif isinstance(payload, list):
            ticks_or_candles = payload
        else:
            return []
        if not ticks_or_candles:
            return []

        # استخدم الفريم من الـ payload إن وُجد، وإلا استخدم period_min المُمرّر
        actual_period = period_min
        if isinstance(period_from_payload, (int, float)) and period_from_payload > 0:
            actual_period = int(period_from_payload)
        period_sec = actual_period * 60  # ثانية لكل شمعة

        # اكتشف الصيغة: ticks أو candles؟
        # Tick: [timestamp, price, direction]  → len=3 وعنصرين رقميين
        # Candle: [time, open, close, high, low, vol]  → len=5-6
        first = ticks_or_candles[0] if isinstance(ticks_or_candles, list) else None
        if isinstance(first, dict):
            # صيغة dict للشموع: {"time","open","high","low","close",...}
            return self._parse_candle_dicts(ticks_or_candles)
        if isinstance(first, list):
            if len(first) >= 5:
                # صيغة OHLC list: [time, open, close, high, low, vol]
                return self._parse_candle_lists(ticks_or_candles)
            elif len(first) >= 2:
                # صيغة tick: [timestamp, price, direction?]
                return self._aggregate_ticks_to_candles(ticks_or_candles, period_sec)
        # إذا وصلنا هنا، فالصيغة غير معروفة
        logger.warning("Unknown history payload format. First item: %s", str(first)[:200])
        return []

    def _parse_candle_dicts(self, candles: List[Dict]) -> List[Dict]:
        """يحلّل صيغة {time, open, high, low, close, volume}."""
        parsed = []
        for c in candles:
            try:
                t = int(c.get("time", c.get("timestamp", 0)) or 0)
                o = float(c.get("open", 0) or 0)
                h = float(c.get("high", c.get("max", 0)) or 0)
                l = float(c.get("low", c.get("min", 0)) or 0)
                cl = float(c.get("close", 0) or 0)
                v = float(c.get("volume", 0) or 0)
                if t > 0:
                    parsed.append({"time": t, "open": o, "high": h,
                                   "low": l, "close": cl, "volume": v})
            except Exception:
                continue
        return parsed

    def _parse_candle_lists(self, candles: List[List]) -> List[Dict]:
        """يحلّل صيغة [time, open, close, high, low, volume] (Quotex-style)."""
        parsed = []
        for c in candles:
            try:
                if len(c) >= 5:
                    parsed.append({
                        "time": int(c[0]), "open": float(c[1]),
                        "high": float(c[3]), "low": float(c[4]),
                        "close": float(c[2]),
                        "volume": float(c[5]) if len(c) > 5 else 0.0,
                    })
            except Exception:
                continue
        return parsed

    def _aggregate_ticks_to_candles(self, ticks: List[List],
                                      period_sec: int) -> List[Dict]:
        """يجمع ticks بصيغة [timestamp, price, direction] إلى شموع OHLC.

        لكل فترة (period_sec ثانية):
          - open  = أول tick price في الفترة
          - high  = أقصى price في الفترة
          - low   = أدنى price في الفترة
          - close = آخر tick price في الفترة
          - volume = عدد الـ ticks في الفترة
          - time  = بداية الفترة (floor timestamp إلى period_sec)
        """
        if not ticks:
            return []
        # جمّع الـ ticks حسب bucket = floor(timestamp / period_sec)
        buckets: Dict[int, List[float]] = {}
        for tick in ticks:
            try:
                if len(tick) < 2:
                    continue
                ts = float(tick[0])
                price = float(tick[1])
                bucket = int(ts // period_sec) * period_sec
                if bucket not in buckets:
                    buckets[bucket] = []
                buckets[bucket].append(price)
            except Exception:
                continue
        # حوّل كل bucket إلى شمعة OHLC
        candles = []
        for bucket_time in sorted(buckets.keys()):
            prices = buckets[bucket_time]
            if not prices:
                continue
            candles.append({
                "time": bucket_time,
                "open": prices[0],
                "high": max(prices),
                "low": min(prices),
                "close": prices[-1],
                "volume": float(len(prices)),
            })
        return candles

    async def close(self) -> bool:
        if self.api:
            return await self.api.close()
        return True


# ==============================================================================
# SECTION 9: CREDENTIALS MANAGEMENT
# ==============================================================================
def load_credentials() -> Optional[Dict[str, str]]:
    """يقرأ التوكن/الإيميل/كلمة المرور من credentials.json. يُعيد None إذا لم توجد."""
    if not BN_CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(BN_CREDENTIALS_FILE.read_text())
        if data.get("token") or (data.get("email") and data.get("password")):
            return data
        return None
    except Exception:
        return None


def save_credentials(token: str = "", email: str = "", password: str = "",
                     is_demo: bool = True, proxy: str = "") -> bool:
    """يحفظ التوكن والإيميل/كلمة المرور ونوع الحساب في credentials.json."""
    try:
        existing = {}
        if BN_CREDENTIALS_FILE.exists():
            try:
                existing = json.loads(BN_CREDENTIALS_FILE.read_text())
            except Exception:
                pass
        if token:
            existing["token"] = token
        if email:
            existing["email"] = email
        if password:
            existing["password"] = password
        existing["is_demo"] = is_demo
        if proxy:
            existing["proxy"] = proxy
        existing["saved_at"] = int(time.time())
        BN_CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        bn_logmsg(f"Failed to save credentials: {e}")
        return False


def decode_jwt_exp(token: str) -> Optional[int]:
    """يستخرج حقل `exp` من JWT (دون التحقق من التوقيع). يُعيد timestamp أو None."""
    if not token or token.count(".") != 2:
        return None
    try:
        import base64
        payload_b64 = token.split(".")[1]
        # أضف padding إن لزم
        payload_b64 += "=" * (-len(payload_b64) % 4)
        decoded = base64.urlsafe_b64decode(payload_b64).decode("utf-8", errors="ignore")
        data = json.loads(decoded)
        if isinstance(data, dict) and "exp" in data:
            return int(data["exp"])
    except Exception:
        return None
    return None


def is_token_expired(token: str, leeway_seconds: int = 30) -> bool:
    """يتحقق إن كان التوكن منتهياً (مع فترة سماح)."""
    exp = decode_jwt_exp(token)
    if not exp:
        return True
    return time.time() >= (exp - leeway_seconds)


# ==============================================================================
# SECTION 9.5: HTTP LOGIN (Browser-based, مطابق لـ qx__1.py)
# ==============================================================================
# نموذج تسجيل الدخول في https://binolla.com/login يحتوي على:
#   - input[name="email"]     (type=text,    id ديناميكي مثل :r0:)
#   - input[name="password"]  (type=password, id ديناميكي مثل :r1:)
#   - input[name="remember"]  (type=checkbox)
#   - input[name="cf-turnstile-response"]  (مخفي - Cloudflare CAPTCHA)
#
# الصفحة React SPA، فلا يوجد <form action="..."> تقليدي.
# الـ JS bundle يبني عنوان الـ API ديناميكياً، لذا نجرب عدة endpoints محتملة:
#   /api/auth/login  /api/login  /api/v1/auth/login  /auth/login  /login
#
# نحاول:
#   1) POST form-urlencoded (مثل qx__1.py تماماً)
#   2) POST JSON  (fallback)
# ونستخرج JWT من:
#   - JSON response body
#   - Set-Cookie header
#   - redirect URL (Fragment)
#   - HTML response (regex search)

# endpoints محتملة لتسجيل الدخول إلى Binolla (تُجرّب بالترتيب)
_LOGIN_ENDPOINTS = (
    "/api/auth/login",
    "/api/login",
    "/api/v1/auth/login",
    "/api/v1/login",
    "/auth/login",
    "/login",
)

# أسماء مفاتيح JSON المحتملة التي قد يحملها الرد
_JWT_JSON_KEYS = (
    "token", "access_token", "auth_token", "authToken",
    "accessToken", "jwt", "binolla_token", "bnn_token", "idToken",
)

# أسماء cookies المحتملة
_JWT_COOKIE_NAMES = (
    "token", "access_token", "auth_token", "jwt",
    "bnn_token", "binolla_session",
)


def _looks_like_jwt(s: str) -> bool:
    """يتحقق هل النص يبدو JWT (header.payload.signature)."""
    if not s or not isinstance(s, str):
        return False
    if s.count(".") != 2:
        return False
    if len(s) < 40:
        return False
    # حاول فك payload
    try:
        import base64 as _b64
        pl = s.split(".")[1]
        pl += "=" * (-len(pl) % 4)
        decoded = _b64.urlsafe_b64decode(pl).decode("utf-8", errors="ignore")
        d = json.loads(decoded)
        return isinstance(d, dict) and ("iss" in d or "sub" in d or "aud" in d or "exp" in d)
    except Exception:
        return False


class Login(Browser):
    """تسجيل دخول HTTP إلى Binolla بنفس بنية qx__1.py Login.

    الاستخدام:
        login = Login(api)
        status, msg = await login(email, password)
    """
    base_url = BN_HOST
    https_base_url = BN_ORIGIN_URL
    login_url = f"{BN_ORIGIN_URL}/login"

    def __init__(self, api, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.api = api
        self.headers = self.get_headers()
        # حافظ على رابط اللغة العربية إن اختار المستخدم
        self.full_url = f"{self.https_base_url}/{getattr(api, 'lang', 'en')}"

    def get_login_page(self) -> Optional[BeautifulSoup]:
        """يحضر صفحة /login لاستخراج أي CSRF token أو cookies أولية."""
        self.headers["Connection"] = "keep-alive"
        self.headers["Accept-Encoding"] = "gzip, deflate, br"
        self.headers["Accept-Language"] = "en-US,en;q=0.9,ar;q=0.8"
        self.headers["Accept"] = ("text/html,application/xhtml+xml,application/xml;q=0.9,"
                                  "image/avif,image/webp,*/*;q=0.8")
        self.headers["Referer"] = self.https_base_url + "/"
        self.headers["Upgrade-Insecure-Requests"] = "1"
        self.headers["Sec-Ch-Ua-Mobile"] = "?0"
        self.headers["Sec-Ch-Ua-Platform"] = '"Windows"'
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-User"] = "?1"
        self.headers["Sec-Fetch-Dest"] = "document"
        self.headers["Sec-Fetch-Mode"] = "navigate"
        self.headers["Dnt"] = "1"
        try:
            self.send_request("GET", self.login_url)
            return self.get_soup()
        except Exception as e:
            logger.warning("GET /login failed: %s", e)
            return None

    def _extract_csrf(self, soup: Optional[BeautifulSoup]) -> Optional[str]:
        """يستخرج CSRF token من meta tag أو input hidden."""
        if not soup:
            return None
        # <meta name="csrf-token" content="...">
        meta = soup.find("meta", {"name": "csrf-token"})
        if meta and meta.get("content"):
            return meta["content"]
        # <input type="hidden" name="_token" value="...">
        for name_attr in ("_token", "csrf_token", "csrf", "_csrf"):
            inp = soup.find("input", {"name": name_attr})
            if inp and inp.get("value"):
                return inp["value"]
        return None

    def _extract_token_from_response(self) -> Optional[str]:
        """يستخرج JWT من آخر استجابة HTTP."""
        if not self.response:
            return None

        # 1) JSON response
        ctype = self.response.headers.get("Content-Type", "").lower()
        if "application/json" in ctype:
            try:
                data = self.response.json()
                if isinstance(data, dict):
                    for key in _JWT_JSON_KEYS:
                        val = data.get(key)
                        if isinstance(val, str) and _looks_like_jwt(val):
                            return val
                    # قد يكون في payload متداخل
                    for k1, v1 in data.items():
                        if isinstance(v1, dict):
                            for k2 in _JWT_JSON_KEYS:
                                val = v1.get(k2)
                                if isinstance(val, str) and _looks_like_jwt(val):
                                    return val
            except Exception:
                pass

        # 2) Set-Cookie
        for c in self.cookies:
            if c.name in _JWT_COOKIE_NAMES and _looks_like_jwt(c.value):
                return c.value

        # 3) HTML / JS في الرد (regex)
        try:
            body = self.response.text or ""
            import re as _re
            m = _re.search(r'["\']token["\']\s*:\s*["\']([^"\']{40,500})["\']', body)
            if m and _looks_like_jwt(m.group(1)):
                return m.group(1)
        except Exception:
            pass

        return None

    async def _post_form(self, data: Dict[str, Any], endpoint: str) -> Tuple[bool, str]:
        """POST كـ form-urlencoded (مثل qx__1.py)."""
        url = self.https_base_url + endpoint
        self.headers["Content-Type"] = "application/x-www-form-urlencoded"
        self.headers["Referer"] = self.login_url
        self.headers["Origin"] = self.https_base_url
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-Mode"] = "cors"
        self.headers["Sec-Fetch-Dest"] = "empty"
        self.headers["Accept"] = "application/json, text/plain, */*"
        self.headers["X-Requested-With"] = "XMLHttpRequest"
        try:
            self.send_request("POST", url, data=data)
        except Exception as e:
            return False, f"POST {endpoint} failed: {e}"
        # تحقق من الرد
        if self.response is None:
            return False, f"No response from {endpoint}"
        # Cloudflare challenge detection
        body = self.response.text or ""
        if self.response.status_code == 403 and "Just a moment" in body:
            return False, (f"Cloudflare challenge at {endpoint} — HTTP login blocked "
                          f"(need Turnstile CAPTCHA solved).")
        if self.response.status_code >= 400:
            return False, f"HTTP {self.response.status_code} from {endpoint}"
        token = self._extract_token_from_response()
        if token:
            return True, token
        return False, f"No JWT in response from {endpoint}"

    async def _post_json(self, data: Dict[str, Any], endpoint: str) -> Tuple[bool, str]:
        """POST كـ JSON (fallback لـ SPA endpoints)."""
        url = self.https_base_url + endpoint
        self.headers["Content-Type"] = "application/json"
        self.headers["Referer"] = self.login_url
        self.headers["Origin"] = self.https_base_url
        self.headers["Sec-Fetch-Site"] = "same-origin"
        self.headers["Sec-Fetch-Mode"] = "cors"
        self.headers["Sec-Fetch-Dest"] = "empty"
        self.headers["Accept"] = "application/json, text/plain, */*"
        self.headers["X-Requested-With"] = "XMLHttpRequest"
        try:
            self.send_request("POST", url, json=data)
        except Exception as e:
            return False, f"POST (JSON) {endpoint} failed: {e}"
        if self.response is None:
            return False, f"No response from {endpoint}"
        body = self.response.text or ""
        if self.response.status_code == 403 and "Just a moment" in body:
            return False, (f"Cloudflare challenge at {endpoint} — HTTP login blocked "
                          f"(need Turnstile CAPTCHA solved).")
        if self.response.status_code >= 400:
            return False, f"HTTP {self.response.status_code} from {endpoint} (JSON)"
        token = self._extract_token_from_response()
        if token:
            return True, token
        return False, f"No JWT in JSON response from {endpoint}"

    def success_login(self) -> Tuple[bool, str]:
        """يتحقق من نجاح تسجيل الدخول بناءً على URL الرد (مثل qx__1.py)."""
        if not self.response:
            return False, "No response"
        # بعد نجاح الدخول، يجب ألا يكون الـ URL ما زال على /login
        url = str(self.response.url)
        if "/login" in url and url.rstrip("/").endswith("/login"):
            return False, "Still on /login — login failed."
        return True, "Login successful."

    async def __call__(self, username: str, password: str,
                       user_data_dir: Optional[str] = None) -> Tuple[bool, str]:
        """المُدخل الرئيسي: username=email, password.

        يُعيد (True, "<JWT>") عند النجاح أو (False, "<error>") عند الفشل.
        """
        # 1) جلب /login لاستخراج CSRF والكوكيز
        soup = self.get_login_page()
        csrf = self._extract_csrf(soup)
        bn_logmsg(f"GET /login — CSRF token: {'found' if csrf else 'none'}")

        # 2) بناء حمولة النموذج (مطابقة لـ qx__1.py + حقول Binolla)
        form_data = {
            "email": username,
            "password": password,
            "remember": "on",  # checkbox value
        }
        if csrf:
            form_data["_token"] = csrf

        # 3) جرّب POST كـ form-urlencoded على كل endpoint
        last_err = ""
        for ep in _LOGIN_ENDPOINTS:
            bn_logmsg(f"Trying POST (form) {ep} ...")
            ok, msg = await self._post_form(form_data, ep)
            if ok:
                # نجاح
                self.cookies_str = self.get_cookies()
                self.api.session_data["cookies"] = self.cookies_str
                self.api.session_data["token"] = msg
                self.api.session_data["user_agent"] = self.headers["User-Agent"]
                return True, msg
            last_err = msg
            # إذا Cloudflare challenge، لا فائدة من المحاولة على endpoints أخرى
            if "Cloudflare" in msg:
                break

        # 4) جرّب POST كـ JSON على كل endpoint (fallback)
        if "Cloudflare" not in last_err:
            json_payload = {
                "email": username,
                "password": password,
                "remember": True,
            }
            for ep in _LOGIN_ENDPOINTS:
                bn_logmsg(f"Trying POST (JSON) {ep} ...")
                ok, msg = await self._post_json(json_payload, ep)
                if ok:
                    self.cookies_str = self.get_cookies()
                    self.api.session_data["cookies"] = self.cookies_str
                    self.api.session_data["token"] = msg
                    self.api.session_data["user_agent"] = self.headers["User-Agent"]
                    return True, msg
                last_err = msg
                if "Cloudflare" in msg:
                    break

        return False, last_err or "Login failed. Invalid email or password."


class Settings(Browser):
    """يجلب إعدادات الحساب من /api/state و /api/dictionaries. مطابق لـ qx__1.py Settings."""

    def __init__(self, api):
        proxies_dict = api._normalize_proxies(api.proxies) if hasattr(api, '_normalize_proxies') else None
        super().__init__(proxies=proxies_dict)
        self.set_headers()
        self.api = api
        self.headers = self.get_headers()

    def get_settings(self):
        """يجلب /api/state — يحتوي على حالة الحساب بعد الدخول."""
        self.headers["content-type"] = "application/json"
        self.headers["referer"] = self.api.https_url + "/"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        self.headers["authorization"] = f'Bearer {self.api.session_data.get("token", "")}'
        try:
            r = self.send_request("GET", f"{self.api.https_url}/api/state")
            if r and r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.warning("GET /api/state failed: %s", e)
        return None

    def get_dictionaries(self):
        """يجلب /api/dictionaries — قائمة الأصول والمعلومات المرجعية."""
        self.headers["content-type"] = "application/json"
        self.headers["cookie"] = self.api.session_data.get("cookies", "")
        self.headers["user-agent"] = self.api.session_data.get("user_agent", "")
        try:
            r = self.send_request("GET", f"{self.api.https_url}/api/dictionaries")
            if r and r.status_code == 200:
                return r.json()
        except Exception as e:
            logger.warning("GET /api/dictionaries failed: %s", e)
        return None


# ==============================================================================
# SECTION 10: ASSET NAME NORMALIZATION
# ==============================================================================
def normalize_asset(raw: str) -> str:
    """يُعيد اسم الأصل بصيغة Binolla الموحّدة: حروف كبيرة + لاحقة _otc.

    أمثلة:
      "EURUSD"     -> "EURUSD_otc"
      "EURUSD_otc" -> "EURUSD_otc"
      "EUR/USD"    -> "EURUSD_otc"
      "eur usd"    -> "EURUSD_otc"
    """
    import re as _re
    s = raw.strip()
    if not s:
        return ""
    s = _re.sub(r'[^a-zA-Z0-9]', '', s)
    if not s:
        return ""
    if s.upper().endswith("OTC"):
        s = s[:-3]
    s = s.upper()
    return f"{s}_otc"


def pretty_asset(symbol: str, timeframe_min: int) -> str:
    base = symbol
    suffix = ""
    if base.upper().endswith("_OTC"):
        base = base[:-4]
        suffix = " · OTC"
    if len(base) == 6 and base.isalpha():
        pretty = f"{base[:3]}/{base[3:]}{suffix}"
    else:
        pretty = f"{base}{suffix}"
    return f"{pretty} (M{timeframe_min})"


# ==============================================================================
# SECTION 11: SAVE CANDLES TO JSON
# ==============================================================================
def save_candles_to_json(candles: List[Dict], asset: str,
                          timeframe_min: int, days: int) -> Optional[Path]:
    if not candles:
        bn_logmsg("No candles to save.")
        return None
    try:
        rnd = random.randint(1000, 9999)
        filename = f"{asset}_{timeframe_min}m_{days}d_{rnd}.json"
        filepath = BN_DATA_DIR / filename
        payload = {
            "asset": asset,
            "timeframe_min": timeframe_min,
            "days": days,
            "count": len(candles),
            "fetched_at": int(time.time()),
            "candles": candles,
        }
        filepath.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
        return filepath
    except Exception as e:
        bn_log_exception("save_candles_to_json", e)
        return None


# ==============================================================================
# SECTION 12: KEEPALIVE & CONNECT HELPERS
# ==============================================================================
async def keepalive_loop(client: "Binolla", stop_event: asyncio.Event) -> None:
    """حلقة نشطة للحفاظ على اتصال WebSocket ومنع "نوم" السيرفر.

    بروتوكول Engine.IO v4 (Socket.IO v4):
    - الخادم يُرسل "2" (PING) كل ~25 ثانية.
    - العميل يردّ بـ "3" (PONG) تلقائياً داخل `BinollaWebsocketClient.on_message`.
    - العميل **لا يجب** أن يُرسل "2" أبداً — ذلك انتهاك للبروتوكول ويُسبب
      إغلاق الاتصال فوراً من الخادم.

    آلية عمل هذه الحلقة (بدون إرسال PING):
    - كل 5 ثوانٍ: نُرسل `quotes/list` لطلب الأسعار اللحظية (يُجبر السيرفر على
      إرسال تحديثات s_quotes/list + يُبقي قناة WebSocket نشطة).
    - كل 30 ثانية: نُرسل `assets/list` لطلب قائمة الأصول المُحدّثة.
    - نراقب `last_message_at` للتحذير فقط (بدون إعادة اتصال قسرية).
    """
    quotes_interval = 5.0   # ثانية بين كل طلب quotes/list
    assets_interval = 30.0  # ثانية بين كل طلب assets/list
    last_quotes_at = 0.0
    last_assets_at = 0.0

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break
        if not client.api:
            continue

        now = time.time()

        # 1) تحقق من صحة الاتصال
        if not client.api.state.check_accepted_connection:
            # لا نرسل شيئاً — الـ watchdog سيتولى إعادة الاتصال
            continue

        # 2) أرسل quotes/list كل 5 ثوانٍ (يجلب الأسعار اللحظية + يُبقي السيرفر نشطاً)
        #    ملاحظة: لا نُرسل Engine.IO PING "2" — ذلك دور الخادم في EIO=4.
        #    إرسال "2" من العميل يُعتبر انتهاك للبروتوكول ويُغلق الاتصال.
        if now - last_quotes_at >= quotes_interval:
            try:
                client.api.subscribe_quotes()
                last_quotes_at = now
            except Exception as e:
                logger.debug("keepalive quotes/list err: %s", e)

        # 3) أرسل assets/list كل 30 ثانية (يجلب قائمة الأصول المُحدّثة)
        if now - last_assets_at >= assets_interval:
            try:
                client.api.fetch_assets()
                last_assets_at = now
            except Exception as e:
                logger.debug("keepalive assets/list err: %s", e)

        # 4) فحص صحي — تحذير فقط، لا نُجبر إعادة الاتصال
        idle = now - client.api.last_message_at
        if idle > 90.0:
            logger.warning("No WebSocket messages in %.0fs (idle). "
                          "Connection may be stale but not forcing reconnect.", idle)


async def connect_binolla(token: str, is_demo: bool = True,
                          max_attempts: int = 3, proxies: Optional[str] = None) -> Optional[Binolla]:
    for attempt in range(1, max_attempts + 1):
        bn_logmsg(f"Connecting to Binolla (attempt {attempt}/{max_attempts})...")
        client = Binolla(token=token, is_demo=is_demo, proxies=proxies)
        try:
            ok, reason = await asyncio.wait_for(client.connect(), timeout=30)
            if ok:
                bn_logmsg(f"{Colors.GREEN}Connected to Binolla (account={'demo' if is_demo else 'real'}).{Colors.RESET}")
                return client
            bn_logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} failed: {reason}{Colors.RESET}")
        except asyncio.TimeoutError:
            bn_logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} timed out.{Colors.RESET}")
            try:
                await client.close()
            except Exception:
                pass
        except Exception as e:
            bn_log_exception(f"connect_binolla#{attempt}", e)
            try:
                await client.close()
            except Exception:
                pass
        await asyncio.sleep(1.5)
    return None


async def jwt_refresh_loop(client: "Binolla", args: Dict[str, Any],
                            stop_event: asyncio.Event) -> None:
    """يُجدّد التوكن (JWT) بصمت قبل انتهاء صلاحيته بـ 120 ثانية.

    آلية العمل:
    - يفحص صلاحية التوكن كل 60 ثانية.
    - إن بقي على انتهاء الصلاحية أقل من 120 ثانية، يُعيد تسجيل الدخول عبر
      HTTP (نفس طريقة email/password المعتادة بدون أي أسئلة).
    - يُحدّث `client.api.token` و`client.api.state.SSID`.
    - **لا يُعيد اتصال WebSocket** — التوكن الجديد يُستخدم فقط إن انقطع الاتصال
      وأراد الـ watchdog إعادة الاتصال. هذا يمنع الحاجة لإعادة الاتصال كل 15 دقيقة.
    - يُحدّث `credentials.json` بالتوكن الجديد.
    """
    email = args.get("email", "")
    password = args.get("password", "")
    if not (email and password):
        logger.info("jwt_refresh_loop: no email/password — refresh disabled.")
        return

    check_interval = 60.0    # فحص كل 60 ثانية
    refresh_lead = 120.0     # حدّث قبل انتهاء الصلاحية بـ 120 ثانية

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=check_interval)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break
        if not client.api:
            continue

        current_token = client.api.token or ""
        if not current_token:
            continue

        # تحقق من الصلاحية
        exp = decode_jwt_exp(current_token)
        if not exp:
            # لا يمكن قراءة الـ exp — تجاهل
            continue
        now = time.time()
        remaining = exp - now
        if remaining > refresh_lead:
            # ما زال هناك وقت — لا حاجة للتحديث
            continue

        # اقترب الانتهاء — حدّث التوكن
        bn_logmsg(f"{Colors.YELLOW}JWT expires in {remaining:.0f}s — refreshing via HTTP login...{Colors.RESET}")
        new_token = await _http_login(args)
        if not new_token:
            bn_logmsg(f"{Colors.RED}JWT refresh failed — will retry in {check_interval:.0f}s.{Colors.RESET}")
            continue

        # حدّث التوكن في كل مكان
        client.api.token = new_token
        client.api.state.SSID = new_token
        client.token = new_token
        # حدّث credentials.json
        save_credentials(
            token=new_token,
            email=email,
            password=password,
            is_demo=args.get("is_demo", True),
            proxy=args.get("proxies", ""),
        )
        exp_new = decode_jwt_exp(new_token)
        if exp_new:
            bn_logmsg(f"{Colors.GREEN}JWT refreshed. New expiry: "
                   f"{datetime.fromtimestamp(exp_new).strftime('%H:%M:%S')}{Colors.RESET}")
        else:
            bn_logmsg(f"{Colors.GREEN}JWT refreshed.{Colors.RESET}")


async def watchdog_reconnect_loop(client: "Binolla", args: Dict[str, Any],
                                    stop_event: asyncio.Event) -> None:
    """يراقب الاتصال ويُعيد الاتصال تلقائياً عند انقطاعه.

    آلية العمل:
    - كل 5 ثوانٍ (بدل 10)، يفحص `state.check_accepted_connection` و`last_message_at`.
    - إن كان الاتصال ميتاً (لا رسائل منذ 30+ ثانية، أو رُفضت المصادقة)،
      يُعيد بناء `BinollaWebsocketClient` بـ JWT محدّث ويُعيد الاتصال.
    - بعد نجاح إعادة الاتصال، يستدعي `restore_subscriptions()` لإعادة كل
      الاشتراكات (asset/list/change + sentiment + quotes + assets) للأصل
      المُتابَع.
    - لا يطلب أي إدخال من المستخدم.
    - يحاول إعادة الاتصال حتى 5 مرات بفواصل متزايدة (1s, 2s, 4s, 8s, 16s).
    """
    check_interval = 10.0     # فحص كل 10 ثوانٍ
    stale_threshold = 180.0   # 3 دقائق بدون رسائل = اتصال ميت فعلاً
    max_reconnect_attempts = 5

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=check_interval)
        except asyncio.TimeoutError:
            pass
        if stop_event.is_set():
            break
        if not client.api:
            continue

        # تحقق من حالة الاتصال
        # مهم: لا نُعيد الاتصال إلا إذا كان check_accepted_connection = False
        # (سُقط من on_close/on_error فعلياً). هذا يمنع إعادة الاتصال
        # غير الضروري عندما يكون السيرفر بطيئاً مؤقتاً.
        connected = client.api.state.check_accepted_connection
        ws_status = client.api.state.status

        if connected:
            # الاتصال سليم — لا نُعيد الاتصال أبداً
            continue
        if ws_status == WebsocketStatus.CONNECTING:
            # ما زال يحاول الاتصال — انتظر
            continue
        # check_accepted_connection = False → انقطع فعلاً (on_close/on_error)
        # نُعيد الاتصال فوراً
        idle = time.time() - client.api.last_message_at

        # الاتصال ميت أو معلّق — أعد الاتصال
        bn_logmsg(f"{Colors.YELLOW}Watchdog: connection dead (connected={connected}, "
               f"idle={idle:.0f}s, status={ws_status.name}). Reconnecting...{Colors.RESET}")

        # أغلق العميل القديم
        try:
            await client.close()
        except Exception:
            pass
        await asyncio.sleep(1.0)

        # احصل على أحدث توكن (جدّده إن انتهى)
        current_token = client.api.token or client.token or ""
        if not current_token or is_token_expired(current_token):
            bn_logmsg(f"{Colors.CYAN}Watchdog: refreshing JWT before reconnect...{Colors.RESET}")
            new_token = await _http_login(args)
            if not new_token:
                bn_logmsg(f"{Colors.RED}Watchdog: refresh failed. Will retry in {check_interval:.0f}s.{Colors.RESET}")
                continue
            current_token = new_token
            client.api.token = new_token
            client.api.state.SSID = new_token
            client.token = new_token

        # أعد بناء الاتصال (حتى 5 محاولات)
        reconnected = False
        for attempt in range(1, max_reconnect_attempts + 1):
            bn_logmsg(f"{Colors.CYAN}Watchdog: reconnect attempt {attempt}/{max_reconnect_attempts}...{Colors.RESET}")
            try:
                ok, reason = await asyncio.wait_for(client.connect(), timeout=30)
                if ok:
                    bn_logmsg(f"{Colors.GREEN}Watchdog: reconnected successfully (attempt {attempt}).{Colors.RESET}")
                    # أعد الاشتراكات بعد نجاح إعادة الاتصال
                    try:
                        client.api.restore_subscriptions()
                        bn_logmsg(f"{Colors.GREEN}Subscriptions restored after reconnect.{Colors.RESET}")
                    except Exception as e:
                        logger.error("Error restoring subscriptions: %s", e)
                    reconnected = True
                    break
                else:
                    bn_logmsg(f"{Colors.RED}Watchdog: reconnect failed: {reason}{Colors.RESET}")
            except asyncio.TimeoutError:
                bn_logmsg(f"{Colors.RED}Watchdog: reconnect timed out (attempt {attempt}).{Colors.RESET}")
            except Exception as e:
                bn_logmsg(f"{Colors.RED}Watchdog: reconnect error (attempt {attempt}): {e}{Colors.RESET}")
            # فاصل متزايد: 1s, 2s, 4s, 8s, 16s
            if attempt < max_reconnect_attempts:
                delay = 2 ** (attempt - 1)
                bn_logmsg(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
        if not reconnected:
            bn_logmsg(f"{Colors.RED}Watchdog: all {max_reconnect_attempts} reconnect attempts failed.{Colors.RESET}")
            bn_logmsg(f"Will retry in {check_interval:.0f}s...")


async def fetch_candles_for_asset(client: Binolla, asset: str, days: int,
                                    timeframe_min: int, idx: int = 1,
                                    total: int = 1) -> List[Dict]:
    display = pretty_asset(asset, timeframe_min)
    bn_logmsg(f"[{idx}/{total}] Fetching candles for {display} ({days} days, M{timeframe_min})...")

    MAX_RETRIES = MAX_FETCH_RETRIES
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if not client.api or not client.api.state.check_accepted_connection:
                bn_logmsg(f"Connection dead before attempt {attempt}; aborting.")
                return []
            candles = await asyncio.wait_for(
                client.fetch_candles(asset, days, timeframe_min, timeout=30),
                timeout=45,
            )
            if candles:
                bn_logmsg(f"{Colors.GREEN}Got {len(candles)} candles.{Colors.RESET}")
                return candles
            bn_logmsg(f"Attempt {attempt}/{MAX_RETRIES}: empty response.")
        except asyncio.TimeoutError:
            bn_logmsg(f"Attempt {attempt}/{MAX_RETRIES}: fetch timed out.")
        except Exception as e:
            bn_logmsg(f"Attempt {attempt}/{MAX_RETRIES} raised: {e}")
        if attempt < MAX_RETRIES:
            delay = min(RETRY_BACKOFF_BASE ** attempt, RETRY_BACKOFF_MAX)
            bn_logmsg(f"Retry in {delay:.1f}s...")
            await asyncio.sleep(delay)
    bn_logmsg(f"All {MAX_RETRIES} attempts failed for {display}")
    return []


# ==============================================================================
# SECTION 13: INTERACTIVE INPUT (async)
# ==============================================================================
async def ainput(prompt: str = "") -> str:
    """input() يمنع الـ event loop؛ نُغلّفه في executor."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, lambda: input(prompt))


def print_banner() -> None:
    banner = r"""
============================================================
  BINOLLA - Binolla Candle Fetcher
  Simplified version: fetch candles and save as JSON
============================================================
  WebSocket : wss://ws3.binolla.com/socket.io/?EIO=4
  Login    : https://binolla.com/login
             (input[name="email"], input[name="password"],
              input[name="remember"])
  Speed    : 5 parallel workers
  Timeframes: 1, 5, 15, 30, 60 (minutes)
============================================================
"""
    print(f"{Colors.CYAN}{banner}{Colors.RESET}")


async def prompt_token() -> Optional[str]:
    """يطلب JWT token من المستخدم. يُعيد None للخروج."""
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Paste JWT token (or 'exit' to quit): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        # تحقق بسيط من الصيغة (3 أجزاء مفصولة بنقاط)
        if raw.count('.') != 2:
            print(f"{Colors.RED}Invalid JWT format (expected 3 dot-separated parts).{Colors.RESET}")
            continue
        return raw


async def prompt_asset() -> Optional[str]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Asset name (e.g. EURUSD_otc, or 'exit'): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        normalized = normalize_asset(raw)
        if not normalized:
            print(f"{Colors.RED}Invalid name.{Colors.RESET}")
            continue
        return normalized


async def prompt_days() -> Optional[int]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Number of days (e.g. 7, 30): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            days = int(float(raw))
            if days <= 0:
                print(f"{Colors.RED}Days must be positive.{Colors.RESET}")
                continue
            return days
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_timeframe() -> Optional[int]:
    while True:
        try:
            raw = (await ainput(
                f"{Colors.YELLOW}Timeframe in minutes (1, 5, 15, 30, 60): {Colors.RESET}"
            )).strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if not raw:
            continue
        if raw.lower() in ('exit', 'quit', 'q'):
            return None
        try:
            tf = int(raw)
            if tf <= 0:
                print(f"{Colors.RED}Timeframe must be positive.{Colors.RESET}")
                continue
            return tf
        except ValueError:
            print(f"{Colors.RED}Please enter a valid integer.{Colors.RESET}")


async def prompt_account_type() -> bool:
    """يُسأل المستخدم: demo أم real. يُعيد True=demo."""
    raw = (await ainput(
        f"{Colors.YELLOW}Account type (D=Demo / R=Real) [D]: {Colors.RESET}"
    )).strip().lower()
    if raw.startswith('r'):
        return False
    return True


async def prompt_email_password() -> Tuple[Optional[str], Optional[str]]:
    """يطلب الإيميل وكلمة المرور من المستخدم.

    يُعيد (None, None) إذا اختار المستخدم الخروج.
    """
    print(f"{Colors.CYAN}Enter your Binolla account credentials:{Colors.RESET}")
    print(f"{Colors.DIM}  These will be sent to binolla.com/login via a real browser.{Colors.RESET}")
    try:
        email = (await ainput(
            f"{Colors.YELLOW}Email: {Colors.RESET}"
        )).strip()
    except (EOFError, KeyboardInterrupt):
        return None, None
    if not email or email.lower() in ('exit', 'quit', 'q'):
        return None, None

    try:
        password = (await ainput(
            f"{Colors.YELLOW}Password: {Colors.RESET}"
        )).strip()
    except (EOFError, KeyboardInterrupt):
        return None, None
    if not password:
        return None, None

    return email, password


# ==============================================================================
# SECTION 13.5: AUTO-LOGIN + ASSET INFO FETCHER (no interactive prompts)
# ==============================================================================
async def auto_login(args: Dict[str, Any]) -> Optional[str]:
    """يسجّل الدخول تلقائياً (بدون أي أسئلة تفاعلية) وفق المنطق التالي:

    1) إذا وُجد توكن في CLI/env ولم ينتهِ، استخدمه مباشرة.
    2) وإلا حمّل credentials.json:
       - إن وُجد JWT صالح هناك، استخدمه.
       - وإلا إن وُجد email/password، أعد تسجيل الدخول عبر HTTP Login.
    3) إن لم ينجح أي شيء، أعد None.

    لا يطلب أي إدخال من المستخدم.
    """
    token = args.get("token", "")
    email = args.get("email", "")
    password = args.get("password", "")

    # 1) توكن من CLI — إن وُجد ولم ينتهِ
    if token and not is_token_expired(token):
        bn_logmsg(f"{Colors.GREEN}Using CLI-provided JWT (still valid).{Colors.RESET}")
        return token

    # 2) حمّل credentials.json
    creds = load_credentials()
    if creds:
        if creds.get("token") and not is_token_expired(creds["token"]):
            bn_logmsg(f"{Colors.GREEN}Using saved JWT from credentials.json (still valid).{Colors.RESET}")
            # املأ email/password من الاعتمادات المحفوظة لاستخدامها لاحقاً عند انتهاء الصلاحية
            if not email and creds.get("email"):
                args["email"] = creds["email"]
            if not password and creds.get("password"):
                args["password"] = creds["password"]
            return creds["token"]

        # الـ JWT منتهٍ — جرّب إعادة الدخول عبر email/password
        if creds.get("email") and creds.get("password"):
            bn_logmsg(f"{Colors.YELLOW}Saved JWT expired — re-logging in via HTTP...{Colors.RESET}")
            args["email"] = creds["email"]
            args["password"] = creds["password"]
            return await _http_login(args)

    # 3) إن وُجد email/password من CLI/env — سجّل الدخول
    if email and password:
        bn_logmsg(f"Logging in as {email} via HTTP (qx__1.py-style)...")
        return await _http_login(args)

    # 4) لا اعتمادات على الإطلاق — اطلب email/password من المستخدم (مرة واحدة)
    bn_logmsg(f"{Colors.CYAN}No credentials found. First-time setup:{Colors.RESET}")
    print(f"{Colors.DIM}  Enter your Binolla account email and password.{Colors.RESET}")
    print(f"{Colors.DIM}  They will be saved to {BN_CREDENTIALS_FILE.name} so you won't be asked again.{Colors.RESET}")
    email_in, password_in = await prompt_email_password()
    if not email_in or not password_in:
        bn_logmsg(f"{Colors.RED}Email and password are required. Exiting.{Colors.RESET}")
        return None

    # احفظهم فوراً في credentials.json (قبل محاولة الدخول لتفادي فقدانهم)
    args["email"] = email_in
    args["password"] = password_in
    save_credentials(
        token="",
        email=email_in,
        password=password_in,
        is_demo=args.get("is_demo", True),
        proxy=args.get("proxies", ""),
    )
    print(f"{Colors.GREEN}Credentials saved to {BN_CREDENTIALS_FILE.name}{Colors.RESET}")
    bn_logmsg(f"Logging in as {email_in} via HTTP (qx__1.py-style)...")
    return await _http_login(args)


async def _http_login(args: Dict[str, Any]) -> Optional[str]:
    """ينفّذ تسجيل الدخول عبر HTTP Login ويعيد التوكن أو None."""
    email = args.get("email", "")
    password = args.get("password", "")
    if not (email and password):
        return None

    from types import SimpleNamespace
    proxy_dict = None
    if args.get("proxies"):
        proxy_dict = {"http": args["proxies"], "https": args["proxies"]}

    login_api = SimpleNamespace(
        host=HOST, https_url=ORIGIN_URL, lang="en",
        session_data={"user_agent": USER_AGENT, "cookies": ""},
        _normalize_proxies=(lambda x: {"http": x, "https": x} if x else None),
        proxies=args.get("proxies") or None,
    )
    login = Login(login_api, proxies=proxy_dict)
    try:
        ok, jwt_or_err = await login(email, password)
    except Exception as e:
        bn_logmsg(f"{Colors.RED}HTTP login exception: {e}{Colors.RESET}")
        return None
    if not ok:
        bn_logmsg(f"{Colors.RED}HTTP login failed: {jwt_or_err}{Colors.RESET}")
        bn_logmsg(f"{Colors.YELLOW}Hint: Binolla uses Cloudflare Turnstile on /login. "
               f"Try logging in via browser once and copy the JWT from DevTools → "
               f"Application → Local Storage → 'token' key.{Colors.RESET}")
        return None
    bn_logmsg(f"{Colors.GREEN}Got JWT from HTTP login.{Colors.RESET}")
    return jwt_or_err


# ==============================================================================
# SECTION 13.6: ASSETS + PAYOUT + LIVE PRICE FETCHER
# ==============================================================================
def _extract_asset_names(assets_payload: Any) -> List[str]:
    """يستخرج أسماء الأصول من حملة s_assets/list بأي صيغة محتملة.

    الصيغ المدعومة:
      - ["EURUSD_otc", "GBPUSD_otc", ...]                (قائمة أسماء)
      - [{"asset":"EURUSD_otc",...}, ...]                 (قائمة dicts)
      - {"assets":[{"asset":"EURUSD_otc",...}, ...]}      (dict مع مفتاح assets)
      - {"EURUSD_otc":{...}, "GBPUSD_otc":{...}}           (dict بأسماء الأصول كمفاتيح)
      - [[ [442,'0700.HK_otc','0700.HK (OTC)','stock',3,93,...], ... ]]  (Binolla tuple format)
        ← قائمة ثلاثية التداخل، كل tuple: [id, asset_code, display_name, type, ...]
    """
    records = _extract_asset_records(assets_payload)
    if records:
        return [r.get("asset", "") for r in records if r.get("asset")]
    return []


def _extract_asset_records(assets_payload: Any) -> List[Dict[str, Any]]:
    """يستخرج سجلات الأصول الكاملة من حملة s_assets/list بأي صيغة.

    الصيغة الفعلية لـ Binolla (كما التُقطت من المتصفح):
        [[[442, '0700.HK_otc', '0700.HK (OTC)', 'stock', 3, 93, None, None, None, 1,
           None, None, None, 1791417600, True, None, 70, 0.93, 93, 93, 0, 0,
           -0.09, -5.87, None, -30.61, 0.04, 0, 0], ...]]

    حيث كل tuple يمثّل أصل، وحقوله (بالترتيب):
        [0]  id              : 442 (int)
        [1]  asset_code      : '0700.HK_otc' (str)  ← اسم الأصل
        [2]  display_name    : '0700.HK (OTC)' (str)
        [3]  type            : 'stock' / 'currency' / 'crypto' / 'commodity'
        [4]  group_id        : 3 (int)
        [5]  payout          : 93 (int, نسبة الدفع %)
        [13] expire_at       : 1791417600 (timestamp)
        [14] is_tradable     : True
        [16] precision       : 70 (int)
        [17] step            : 0.93 (float)
        [18] bid             : 93 (float)
        [19] ask             : 93 (float)

    يُعيد قائمة dicts بصيغة موحّدة:
        [{"id":..., "asset":..., "name":..., "type":..., "payout":..., ...}]
    """
    if assets_payload is None:
        return []

    # فك التداخل: [[[item1, item2, ...]]] → [item1, item2, ...]
    items = _flatten_nested_lists(assets_payload)
    if not isinstance(items, list):
        return []

    records: List[Dict[str, Any]] = []
    for item in items:
        if isinstance(item, dict):
            # صيغة dict
            name = (item.get("asset") or item.get("name")
                     or item.get("symbol") or item.get("code"))
            if name:
                records.append({
                    "asset": name,
                    "name": item.get("display_name") or item.get("label") or name,
                    "type": item.get("type") or item.get("category"),
                    "payout": item.get("payout") or item.get("profit")
                              or item.get("sentiment"),
                    "raw": item,
                })
        elif isinstance(item, (list, tuple)) and len(item) >= 2:
            # صيغة Binolla tuple: [id, asset_code, display_name, type, group, payout, ...]
            try:
                rec = {
                    "id": item[0] if len(item) > 0 else None,
                    "asset": item[1] if len(item) > 1 else "",
                    "name": item[2] if len(item) > 2 else item[1],
                    "type": item[3] if len(item) > 3 else "",
                    "group_id": item[4] if len(item) > 4 else None,
                    "payout": item[5] if len(item) > 5 else None,
                    "expire_at": item[13] if len(item) > 13 else None,
                    "is_tradable": item[14] if len(item) > 14 else None,
                    "precision": item[16] if len(item) > 16 else None,
                    "step": item[17] if len(item) > 17 else None,
                    "bid": item[18] if len(item) > 18 else None,
                    "ask": item[19] if len(item) > 19 else None,
                    "raw": list(item),
                }
                if rec["asset"]:
                    records.append(rec)
            except Exception as e:
                logger.debug("Error parsing asset tuple: %s", e)
    return records


def _flatten_nested_lists(payload: Any) -> List[Any]:
    """يأخذ payload ويفك أي تداخل حتى يصل إلى قائمة "الصفوف".

    مثال:
        [[[item1, item2], [item3]], ...]  →  [item1, item2, item3]
        [item1, item2]                    →  [item1, item2]
        [[[item1, item2, ...]]]           →  [item1, item2, ...]
    """
    if not isinstance(payload, list):
        return []
    if not payload:
        return []
    # تحقق من البند الأول — إن كان سجل أصل حقيقياً (dict أو list بطول ≥ 2)
    # فالـ payload نفسه هو قائمة السجلات.
    first = payload[0]
    if isinstance(first, dict):
        return payload
    if isinstance(first, (list, tuple)) and len(first) >= 2:
        # تحقق إن كان first هو tuple لأصل (يحتوي على str في index 1)
        # أم هو قائمة من tuples (تداخل آخر).
        if len(first) >= 2 and isinstance(first[1], (list, tuple)):
            # first نفسها قائمة من tuples → قم بفك طبقة واحدة
            flattened: List[Any] = []
            for sub in payload:
                if isinstance(sub, (list, tuple)):
                    flattened.extend(sub)
                else:
                    flattened.append(sub)
            return flattened
        # first هي tuple لأصل حقيقي
        return payload
    # أي شيء آخر
    return []


def _normalize_asset_for_quote(name: str) -> str:
    """يُعيد اسم الأصل بصيغة موحدة للاقتران مع quotes/sentiment."""
    if not name:
        return ""
    s = name.strip()
    return s


def _format_asset_status(rec: Dict[str, Any]) -> Tuple[str, str]:
    """يُعيد (status_text, color) لحالة الأصل (مفتوح/مغلق).

    يعتمد على:
      - rec['is_tradable'] (True/False/None) من tuple position 14
      - rec['expire_at'] (Unix timestamp) من tuple position 13
        → إن انتهت مدة الصلاحية، يُعتبر مغلقاً

    يُعيد:
      - ("OPEN", Colors.GREEN)   ← مفتوح للتداول
      - ("CLOSED", Colors.RED)    ← مغلق للتداول
      - ("?", Colors.DIM)         ← غير معروف
    """
    is_tradable = rec.get("is_tradable")
    expire_at = rec.get("expire_at")

    # إن وُجد expire_at وانتهى، اعتبره مغلقاً
    if isinstance(expire_at, (int, float)) and expire_at > 0:
        if time.time() > expire_at:
            return ("CLOSED", Colors.RED)

    if is_tradable is True:
        return ("OPEN", Colors.GREEN)
    if is_tradable is False:
        return ("CLOSED", Colors.RED)
    # غير معروف
    return ("?", Colors.DIM)


def save_assets_info_to_json(payload: Dict[str, Any],
                              out_path: Optional[Path] = None) -> Path:
    """يحفظ بيانات الأصول (الاسم، نسبة الدفع، السعر اللحظي) في ملف JSON."""
    if out_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_path = BN_DATA_DIR / f"assets_info_{ts}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False,
                                    default=str))
    return out_path


async def fetch_all_assets_info(client: "Binolla",
                                 wait_seconds: float = 8.0) -> Dict[str, Any]:
    """يجلب كل الأصول المتوفرة + نسبة الدفع + السعر اللحظي.

    الخطوات:
      1) يطلب assets/list وينتظر s_assets/list.
      2) يشترك في sentiment العام (s_asset/sentiment/subscribe).
      3) لكل أصل، يُرسل asset/sentiment/subscribe وasset/list/change وquotes/list
         لجلب نسبة الدفع والسعر اللحظي.
      4) ينتظر wait_seconds لتجميع كل التحديثات.
      5) يجمع النتائج في قائمة dicts.

    النتيجة:
        {
          "fetched_at": <unix_ts>,
          "assets_count": N,
          "assets": [
            {"asset":"EURUSD_otc", "payout":17, "price":1.0823, "signals":{...}, "raw":{...}},
            ...
          ]
        }
    """
    api = client.api
    if not api:
        return {"error": "API not connected", "assets": []}

    # 1) اطلب قائمة الأصول (وإن لم تصل بعد)
    bn_logmsg(f"{Colors.CYAN}Requesting assets/list...{Colors.RESET}")
    await api.event_registry.clear_event("s_assets/list")
    api.fetch_assets()
    assets_payload = await api.event_registry.wait_event(
        "s_assets/list", timeout=10.0)
    if not assets_payload:
        # ربما وصلت تلقائياً بعد المصادقة
        assets_payload = api.assets_list
    if not assets_payload:
        bn_logmsg(f"{Colors.RED}No assets/list received.{Colors.RESET}")
        return {"error": "no assets/list", "assets": []}

    api.assets_list = assets_payload
    asset_names = _extract_asset_names(assets_payload)
    bn_logmsg(f"{Colors.GREEN}Got {len(asset_names)} assets.{Colors.RESET}")
    logger.debug("First 10 assets: %s", asset_names[:10])

    # 2) اشترك في sentiment العام (يصل لكل الأصول تدريجياً)
    bn_logmsg(f"{Colors.CYAN}Subscribing to global sentiment (s_asset/sentiment)...{Colors.RESET}")
    api.subscribe_global_sentiment()

    # 3) لكل أصل، اشترك في sentiment + quotes + signals
    #    نرسل بشكل دفعي لكن بفاصل قصير لتفادي الـ rate-limiting.
    bn_logmsg(f"{Colors.CYAN}Subscribing per-asset sentiment + quotes + signals "
           f"({len(asset_names)} assets)...{Colors.RESET}")
    BATCH = 25
    for i in range(0, len(asset_names), BATCH):
        batch = asset_names[i:i + BATCH]
        for name in batch:
            try:
                api.subscribe_asset_sentiment(name)
            except Exception as e:
                logger.debug("subscribe_asset_sentiment(%s) err: %s", name, e)
            try:
                # نشترك في signals لفريمات شائعة
                api.subscribe_asset_signals(name, timeframes=[60, 300, 900])
            except Exception as e:
                logger.debug("subscribe_asset_signals(%s) err: %s", name, e)
        # طلب quotes/list لتحديث الأسعار اللحظية لكل الأصول
        try:
            api.subscribe_quotes()
        except Exception as e:
            logger.debug("subscribe_quotes err: %s", e)
        # فاصل قصير بين الدفعات
        await asyncio.sleep(0.3)

    # 4) انتظر تجميع التحديثات
    bn_logmsg(f"{Colors.CYAN}Waiting {wait_seconds:.1f}s to collect sentiment + quotes...{Colors.RESET}")
    await asyncio.sleep(wait_seconds)

    # 5) اجمع النتائج
    assets_info: List[Dict[str, Any]] = []
    for name in asset_names:
        sentiment_data = api.assets_sentiment.get(name, {})
        payout = None
        if isinstance(sentiment_data, dict):
            payout = sentiment_data.get("sentiment",
                                         sentiment_data.get("payout",
                                         sentiment_data.get("profit")))
        quote_data = api.assets_quotes.get(name)
        price = None
        if isinstance(quote_data, dict):
            for k in ("price", "value", "rate", "last"):
                if k in quote_data:
                    price = quote_data[k]
                    break
        elif isinstance(quote_data, (int, float)):
            price = float(quote_data)
        signals = api.assets_signals.get(name, {})
        assets_info.append({
            "asset": name,
            "payout": payout,
            "price": price,
            "signals": {str(k): v for k, v in signals.items()},
            "sentiment_raw": sentiment_data,
            "quote_raw": quote_data,
        })

    return {
        "fetched_at": int(time.time()),
        "assets_count": len(assets_info),
        "assets": assets_info,
    }


# ==============================================================================
# SECTION 14: COMMAND-LINE INTERFACE
# ==============================================================================
def parse_args() -> Dict[str, Any]:
    """معالجة بسيطة لوسائط سطر الأوامر.

    الافتراضي: DEMO account (بدون أي أسئلة تفاعلية).
    استخدم --real للتبديل إلى حساب حقيقي.
    """
    args = {
        "token": os.environ.get("BINOLLA_TOKEN", ""),
        "email": os.environ.get("BINOLLA_EMAIL", ""),
        "password": os.environ.get("BINOLLA_PASSWORD", ""),
        "asset": os.environ.get("BINOLLA_ASSET", ""),
        "days": int(os.environ.get("BINOLLA_DAYS", "0")),
        "timeframe": int(os.environ.get("BINOLLA_TIMEFRAME", "1")),
        # الافتراضي: DEMO (السلوك المطلوب من المستخدم)
        "is_demo": os.environ.get("BINOLLA_ACCOUNT", "demo").lower() != "real",
        "proxies": os.environ.get("BINOLLA_PROXY", ""),
        "headless": os.environ.get("BINOLLA_HEADLESS", "0") == "1",
        "non_interactive": True,   # دائماً non-interactive الآن
    }
    # وسيطات سطر الأوامر البسيطة
    rest = sys.argv[1:]
    i = 0
    while i < len(rest):
        a = rest[i]
        if a in ("--token",) and i + 1 < len(rest):
            args["token"] = rest[i + 1]; i += 2; continue
        if a in ("--email",) and i + 1 < len(rest):
            args["email"] = rest[i + 1]; i += 2; continue
        if a in ("--password", "--pass") and i + 1 < len(rest):
            args["password"] = rest[i + 1]; i += 2; continue
        if a in ("--asset",) and i + 1 < len(rest):
            args["asset"] = rest[i + 1]; i += 2; continue
        if a in ("--days",) and i + 1 < len(rest):
            args["days"] = int(rest[i + 1]); i += 2; continue
        if a in ("--period", "--timeframe") and i + 1 < len(rest):
            args["timeframe"] = int(rest[i + 1]); i += 2; continue
        if a in ("--real",):
            args["is_demo"] = False; i += 1; continue
        if a in ("--demo",):
            args["is_demo"] = True; i += 1; continue
        if a in ("--proxy",) and i + 1 < len(rest):
            args["proxies"] = rest[i + 1]; i += 2; continue
        if a in ("--headless",):
            args["headless"] = True; i += 1; continue
        if a in ("--non-interactive", "--yes", "-y"):
            args["non_interactive"] = True; i += 1; continue
        if a in ("-h", "--help"):
            print(__doc__)
            sys.exit(0)
        i += 1
    return args


# ==============================================================================
# SECTION 14.5: LIVE PRICE STREAM (event-driven, continuous)
# ==============================================================================
def _is_likely_timestamp(value: float) -> bool:
    """يتحقق هل القيمة تبدو Unix timestamp (وليست سعراً).

    أسعار الفوركس/الأسهم عادةً < 100000 (حتى BTC ~$100k).
    Unix timestamps منذ 2001-09-09 = 1,000,000,000 (1e9).
    منذ 2001 = 1e9، منذ 2020 = 1.5e9، منذ 2026 = 1.79e9.

    أي قيمة >= 1e9 تُعتبر timestamp وليست سعراً.
    """
    if not isinstance(value, (int, float)):
        return False
    return abs(value) >= 1_000_000_000   # 1e9 = Sept 2001


class LivePriceStream:
    """يبث الأسعار اللحظية بشكل مستمر — يُطبع كل تحديث سعر فور وصوله.

    آلية العمل:
    - يُسجّل نفسه كمعالج (handler) لحدث `s_quotes/list` في BinollaAPI.
    - كلما وصل تحديث أسعار من WebSocket، يُستدعى `handler()` فوراً.
    - يطبّق throttling بسيط: max طبعة واحدة لكل أصل كل 0.3 ثانية (لتفادي الفيض).
    - يدعم "watch mode": تخصيص أصل واحد لمتابعته حصرياً.

    الاستخدام:
        stream = LivePriceStream(api)
        api.register_handler("s_quotes/list", stream.handler)
        stream.start()
    """

    def __init__(self, api: "BinollaAPI", watch_asset: Optional[str] = None,
                 min_interval: float = 0.3):
        self.api = api
        self.watch_asset = watch_asset    # None = كل الأصول
        self.min_interval = min_interval  # ثانية بين طبعتين لنفس الأصل
        self._last_print: Dict[str, float] = {}
        self._enabled = True
        self._print_count = 0
        self.debug = False   # وضع debug: يطبع اسم كل حدث يصل

    def start(self) -> None:
        """يسجّل المعالج على s_quotes/list وs_asset/sentiment وs_history/last."""
        if self.api:
            self.api.register_handler("s_quotes/list", self._on_quotes)
            self.api.register_handler("s_asset/sentiment", self._on_sentiment)
            self.api.register_handler("s_history/last", self._on_history_last)

    def stop(self) -> None:
        """يوقف البث (المعالج يبقى مُسجّلاً لكنه لا يطبع)."""
        self._enabled = False
        # أعطّل flag لكي logmsg يطبع بشكل طبيعي
        set_live_stream_active(False)
        # اطبع سطراً جديداً ليفصل البث عن الرسائل التالية
        sys.stdout.write("\n")
        sys.stdout.flush()

    def resume(self) -> None:
        """يستأنف البث."""
        self._enabled = True
        set_live_stream_active(True)

    def set_watch(self, asset: Optional[str]) -> None:
        """None = بث كل الأصول، أو اسم أصل لمتابعته حصرياً.

        يُخزّن أيضاً في api.watch_asset ليُستعاد بعد إعادة اتصال WebSocket.
        """
        self.watch_asset = asset.strip().upper() if asset else None
        self._last_print.clear()
        # خزّن في API للاستعادة بعد reconnect
        if self.api:
            self.api.watch_asset = self.watch_asset
            # حدّث current_asset أيضاً (يُستخدم في fallback لاسم الأصل)
            if self.watch_asset:
                self.api.current_asset = self.watch_asset

    def set_debug(self, enabled: bool) -> None:
        """يُفعّل/يُعطّل وضع debug (يطبع اسم كل حدث يصل)."""
        self.debug = enabled

    def _on_quotes(self, *args) -> None:
        """يُستدعى عند وصول s_quotes/list. يطبع الأسعار فوراً."""
        if not self._enabled and not self.debug:
            return
        if not args:
            return
        payload = args[0]
        if self.debug:
            ts = datetime.now().strftime("%H:%M:%S")
            preview = str(payload)[:200]
            print(f"  {Colors.DIM}[{ts}] DEBUG s_quotes/list: {preview}{Colors.RESET}")
        if not self._enabled:
            return
        # قد تكون القائمة من dicts أو tuples أو قيمة بسيطة
        items = payload if isinstance(payload, list) else [payload]
        now = time.time()
        for item in items:
            asset, price = self._extract_asset_and_price(item)
            if not asset:
                continue
            if self.watch_asset and asset.upper() != self.watch_asset:
                continue
            last = self._last_print.get(asset, 0)
            if now - last < self.min_interval:
                continue
            self._last_print[asset] = now
            self._print_quote(asset, price)

    def _on_history_last(self, *args) -> None:
        """يُستدعى عند وصول s_history/last. يحتوي على أحدث ticks للأصل الحالي.

        بنية payload المحتملة:
          - {"asset":"XTIUSD_otc", "history":[[ts, price, dir], ...]}
          - {"asset":"XTIUSD_otc", "candles":[[time, o, c, h, l, v], ...]}
          - [[ts, price, dir], ...]  (قائمة ticks مباشرة)
        آخر tick/شمعة يحتوي على السعر اللحظي.
        """
        if not self._enabled and not self.debug:
            return
        if not args:
            return
        payload = args[0]
        if self.debug:
            ts = datetime.now().strftime("%H:%M:%S")
            preview = str(payload)[:200]
            print(f"  {Colors.DIM}[{ts}] DEBUG s_history/last: {preview}{Colors.RESET}")
        if not self._enabled:
            return

        # استخرج اسم الأصل والسعر
        asset_name = None
        if isinstance(payload, dict):
            asset_name = payload.get("asset") or payload.get("symbol")
        # fallback: استخدم الأصل الحالي من API
        if not asset_name and self.api:
            asset_name = self.api.current_asset
        if not asset_name and self.watch_asset:
            asset_name = self.watch_asset
        if not asset_name:
            return

        if self.watch_asset and asset_name.upper() != self.watch_asset:
            return

        price = self._extract_latest_price(payload)
        if price is None:
            return

        now = time.time()
        last = self._last_print.get(asset_name, 0)
        if now - last < self.min_interval:
            # حتى مع throttling، حدّث المخزن المؤقت
            if self.api:
                self.api.assets_quotes[asset_name] = {"price": price}
            return
        self._last_print[asset_name] = now
        # حدّث المخزن المؤقت
        if self.api:
            self.api.assets_quotes[asset_name] = {"price": price}
        self._print_quote(asset_name, price)

    def _extract_asset_and_price(self, item: Any) -> Tuple[Optional[str], Optional[float]]:
        """يستخرج اسم الأصل والسعر من عنصر quote بأي صيغة محتملة.

        الصيغ المدعومة:
          - {"asset":"EURUSD_otc", "price":1.0823, ...}
          - {"asset":"EURUSD_otc", "bid":1.0823, "ask":1.0825, ...}
          - ("EURUSD_otc", 1.0823)  (tuple)
          - ["EURUSD_otc", 1.0823]  (list)
          - 1.0823  (قيمة بسيطة — يستخدم اسم الأصل الحالي)

        مهم: يرفض القيم التي تبدو timestamps (Unix time) بدلاً من أسعار.
        """
        if isinstance(item, dict):
            asset = item.get("asset") or item.get("name") or item.get("symbol")
            price = None
            for k in ("price", "bid", "ask", "close", "rate", "last", "value"):
                if k in item:
                    try:
                        candidate = float(item[k])
                        if not _is_likely_timestamp(candidate):
                            price = candidate
                            break
                    except (ValueError, TypeError):
                        continue
            return asset, price
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            asset = item[0] if isinstance(item[0], str) else None
            # جرّب كل المواضع لإيجاد قيمة تبدو سعراً (وليست timestamp)
            price = None
            for idx in range(1, len(item)):
                try:
                    candidate = float(item[idx])
                    if not _is_likely_timestamp(candidate):
                        price = candidate
                        break
                except (ValueError, TypeError):
                    continue
            return asset, price
        # قيمة بسيطة — استخدم الأصل الحالي
        if isinstance(item, (int, float)):
            asset = self.watch_asset or (self.api.current_asset if self.api else None)
            try:
                val = float(item)
                if _is_likely_timestamp(val):
                    return asset, None
                return asset, val
            except (ValueError, TypeError):
                return asset, None
        return None, None

    def _extract_latest_price(self, payload: Any) -> Optional[float]:
        """يستخرج آخر سعر من payload الـ history/last.

        يحاول عدة صيغ:
          - {"history":[[ts, price, dir], ...]}  ← tick format
          - {"candles":[[time, o, c, h, l, v], ...]}  ← candle list format
          - {"candles":[{"time","open","close",...}, ...]}  ← candle dict format
          - [[ts, price, dir], ...]  (قائمة ticks مباشرة)

        مهم: يرفض القيم التي تبدو timestamps (Unix time).
        """
        ticks_or_candles = None
        if isinstance(payload, dict):
            ticks_or_candles = (payload.get("history") or payload.get("candles")
                                or payload.get("data") or payload.get("list")
                                or payload.get("ticks"))
            if ticks_or_candles is None and isinstance(payload.get("data"), dict):
                ticks_or_candles = (payload["data"].get("candles")
                                     or payload["data"].get("history") or [])
        elif isinstance(payload, list):
            ticks_or_candles = payload
        if not ticks_or_candles or not isinstance(ticks_or_candles, list):
            return None
        if not ticks_or_candles:
            return None
        # ابحث في آخر tick/شمعة، وإن كان سعره يبدو timestamp، جرّب السابق
        for idx in range(len(ticks_or_candles) - 1, -1, -1):
            last = ticks_or_candles[idx]
            price = self._extract_price_from_tick_or_candle(last)
            if price is not None and not _is_likely_timestamp(price):
                return price
        return None

    def _extract_price_from_tick_or_candle(self, item: Any) -> Optional[float]:
        """يستخرج السعر من tick أو candle واحد.
        - tick: [ts, price, dir]  → يجرّب index 1 ثم 2
        - candle list: [time, o, c, h, l, v]  → يجرّب index 2 (close) ثم 1 (open)
        - candle dict: {"price":...} أو {"close":...}
        يرفض القيم التي تبدو timestamps.
        """
        if isinstance(item, (list, tuple)):
            for idx in (1, 2, 3):
                if idx < len(item):
                    try:
                        candidate = float(item[idx])
                        if not _is_likely_timestamp(candidate):
                            return candidate
                    except (ValueError, TypeError):
                        continue
        elif isinstance(item, dict):
            for k in ("price", "close", "bid", "ask", "rate", "last", "value"):
                if k in item:
                    try:
                        candidate = float(item[k])
                        if not _is_likely_timestamp(candidate):
                            return candidate
                    except (ValueError, TypeError):
                        continue
        return None

    def _on_sentiment(self, *args) -> None:
        """يُستدعى عند وصول s_asset/sentiment. يطبع نسبة الدفع فوراً."""
        if not self._enabled and not self.debug:
            return
        if not args:
            return
        payload = args[0]
        if self.debug:
            ts = datetime.now().strftime("%H:%M:%S")
            preview = str(payload)[:200]
            print(f"  {Colors.DIM}[{ts}] DEBUG s_asset/sentiment: {preview}{Colors.RESET}")
        if not self._enabled:
            return
        items = payload if isinstance(payload, list) else [payload]
        for item in items:
            if not isinstance(item, dict) or "asset" not in item:
                continue
            asset = item["asset"]
            if self.watch_asset and asset.upper() != self.watch_asset:
                continue
            payout = item.get("sentiment",
                              item.get("payout",
                                       item.get("profit")))
            ts = datetime.now().strftime("%H:%M:%S")
            payout_str = f"{payout}%" if payout is not None else "—"
            print(f"  {Colors.YELLOW}[{ts}] PAYOUT {Colors.RESET}"
                  f"{asset:<20} {payout_str}")

    def _print_quote(self, asset: str, price_or_item: Any) -> None:
        """يطبع/يحدّث سطر السعر اللحظي على نفس السطر (inline update).

        يستخدم carriage return (\\r) للكتابة فوق نفس السطر بدلاً من طباعة سطر جديد.
        يقبل إما:
          - قيمة سعر مباشرة (float/int)
          - أو dict يحتوي على مفتاح سعر
        """
        price = None
        if isinstance(price_or_item, (int, float)):
            candidate = float(price_or_item)
            if not _is_likely_timestamp(candidate):
                price = candidate
        elif isinstance(price_or_item, dict):
            for k in ("price", "bid", "ask", "close", "rate", "last", "value"):
                if k in price_or_item:
                    try:
                        candidate = float(price_or_item[k])
                        if not _is_likely_timestamp(candidate):
                            price = candidate
                            break
                    except (ValueError, TypeError):
                        continue
        sent = self.api.assets_sentiment.get(asset, {}) if self.api else {}
        payout = sent.get("sentiment") if isinstance(sent, dict) else None
        ts = datetime.now().strftime("%H:%M:%S")
        payout_str = f"{payout}%" if payout is not None else "—"
        price_str = f"{price}" if price is not None else "waiting..."
        # جلب حالة الأصل (مفتوح/مغلق) من قائمة الأصول المُخزّنة
        status_str = ""
        if self.api and self.api.assets_list:
            records = _extract_asset_records(self.api.assets_list)
            rec = next((r for r in records if r.get("asset") == asset), None)
            if rec:
                status_text, status_color = _format_asset_status(rec)
                status_str = f"{status_color}{status_text:<7}{Colors.RESET} "
        self._print_count += 1
        # فعّل flag لكي logmsg لا تكتب فوق السعر
        set_live_stream_active(True)
        # استخدم \r للكتابة فوق نفس السطر (inline update)
        # \033[K يمسح باقي السطر لتفادي اختلاط النصوص
        line = (f"\r\033[K  {Colors.DIM}[{ts}]#{self._print_count}{Colors.RESET} "
                f"{Colors.GREEN}{asset:<20}{Colors.RESET} "
                f"{status_str}"
                f"payout={payout_str:<6} "
                f"price={Colors.CYAN}{price_str}{Colors.RESET}")
        sys.stdout.write(line)
        sys.stdout.flush()


# ==============================================================================
# SECTION 14.6: INTERACTIVE COMMAND PROCESSOR
# ==============================================================================
async def cmd_assets(client: "Binolla", live_stream: LivePriceStream) -> None:
    """يجلب قائمة كل الأصول ويطبعها مع نسبة الدفع والسعر اللحظي بجوارها.

    بنية payload من Binolla (كما التُقطت):
        [[[442, '0700.HK_otc', '0700.HK (OTC)', 'stock', 3, 93, ...], ...]]
    حيث:
      [1] = asset code (مثل '0700.HK_otc')
      [2] = display name (مثل '0700.HK (OTC)')
      [3] = type (مثل 'stock', 'currency', 'crypto')
      [5] = payout % (مدمج في tuple مباشرة!)
      [18]/[19] = bid/ask
    """
    if not client.api:
        print(f"{Colors.RED}API not connected.{Colors.RESET}")
        return
    print(f"\n{Colors.CYAN}Fetching assets/list...{Colors.RESET}")
    await client.api.event_registry.clear_event("s_assets/list")
    client.api.fetch_assets()
    payload = await client.api.event_registry.wait_event(
        "s_assets/list", timeout=10.0)
    if not payload:
        payload = client.api.assets_list
    if not payload:
        print(f"{Colors.RED}No assets received.{Colors.RESET}")
        return
    client.api.assets_list = payload

    # استخدم السجلات الكاملة (تدعم tuple format و dict format)
    records = _extract_asset_records(payload)
    if not records:
        # fallback للأسماء فقط
        asset_names = _extract_asset_names(payload)
        if not asset_names:
            print(f"{Colors.RED}Could not extract asset names from payload.{Colors.RESET}")
            print(f"{Colors.DIM}Payload preview: {str(payload)[:300]}{Colors.RESET}")
            return
        # ابنِ سجلات بسيطة من الأسماء
        records = [{"asset": name, "name": name, "type": "", "payout": None}
                   for name in asset_names]

    print(f"\n{Colors.GREEN}Total assets: {len(records)}{Colors.RESET}")

    # تجميع حسب النوع للعرض
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for rec in records:
        t = rec.get("type") or "other"
        by_type.setdefault(t, []).append(rec)

    print(f"\n{Colors.BOLD}By type:{Colors.RESET} " +
          "  ".join(f"{t}={len(recs)}" for t, recs in sorted(by_type.items())))

    # إحصاءات الحالة (مفتوح/مغلق)
    open_count = sum(1 for r in records if _format_asset_status(r)[0] == "OPEN")
    closed_count = sum(1 for r in records if _format_asset_status(r)[0] == "CLOSED")
    print(f"{Colors.BOLD}By status:{Colors.RESET} " +
          f"{Colors.GREEN}OPEN={open_count}{Colors.RESET}  " +
          f"{Colors.RED}CLOSED={closed_count}{Colors.RESET}")

    print(f"\n{Colors.BOLD}{'#':<4} {'Asset':<22} {'Name':<24} {'Type':<10} "
          f"{'Status':<8} {'Payout%':<10} {'Price':<15}{Colors.RESET}")
    print(f"    {'-'*22} {'-'*24} {'-'*10} {'-'*8} {'-'*10} {'-'*15}")
    for i, rec in enumerate(records, 1):
        name = rec.get("asset", "")
        display = rec.get("name", name)[:22]
        atype = rec.get("type", "")[:10]
        # حالة الأصل (مفتوح/مغلق)
        status_text, status_color = _format_asset_status(rec)
        status_str = f"{status_color}{status_text:<8}{Colors.RESET}"
        # payout من السجل نفسه (من tuple) أو من sentiment المُلتقَط
        payout = rec.get("payout")
        if payout is None:
            sent = client.api.assets_sentiment.get(name, {})
            payout = sent.get("sentiment") if isinstance(sent, dict) else None
        # السعر اللحظي
        quote = client.api.assets_quotes.get(name)
        price = None
        if isinstance(quote, dict):
            for k in ("price", "value", "rate", "last", "bid", "ask"):
                if k in quote:
                    price = quote[k]; break
        elif isinstance(quote, (int, float)):
            price = float(quote)
        # fallback لـ bid/ask من السجل نفسه
        if price is None:
            if rec.get("bid") is not None:
                price = rec["bid"]
            elif rec.get("ask") is not None:
                price = rec["ask"]
        payout_str = f"{payout}%" if payout is not None else "—"
        price_str = f"{price}" if price is not None else "—"
        print(f"  {i:<4} {name:<22} {display:<24} {atype:<10} {status_str} {payout_str:<10} {price_str:<15}")

    # اعرض الإحصاءات النهائية
    with_payout = sum(1 for r in records if r.get("payout") is not None)
    with_price = sum(1 for r in records if (r.get("bid") is not None
                                            or r.get("ask") is not None
                                            or r["asset"] in client.api.assets_quotes))
    print(f"\n{Colors.CYAN}Summary:{Colors.RESET} "
          f"total={len(records)}  "
          f"{Colors.GREEN}open={open_count}{Colors.RESET}  "
          f"{Colors.RED}closed={closed_count}{Colors.RESET}  "
          f"with_payout={with_payout}  "
          f"with_price={with_price}")
    print(f"{Colors.DIM}Tip: type 'watch <asset>' to focus live stream on one asset.{Colors.RESET}")
    print(f"{Colors.DIM}     type 'candles EURUSD_otc 7 1' to fetch historical candles.{Colors.RESET}")


async def cmd_payout(client: "Binolla", live_stream: LivePriceStream,
                      asset_arg: Optional[str] = None) -> None:
    """يطبع نسبة الدفع الحالية لكل الأصول (أو لأصل محدد إن طُلب)."""
    if not client.api:
        return
    if asset_arg:
        # اشترك في sentiment لأصل محدد وانتظر التحديث
        asset = asset_arg.strip()
        print(f"{Colors.CYAN}Subscribing to sentiment for {asset}...{Colors.RESET}")
        client.api.subscribe_asset_sentiment(asset)
        await asyncio.sleep(1.5)
        sent = client.api.assets_sentiment.get(asset, {})
        payout = sent.get("sentiment") if isinstance(sent, dict) else None
        if payout is not None:
            print(f"  {asset:<22} payout={payout}%")
        else:
            print(f"  {asset}: no sentiment yet. Try again in a few seconds.")
        return
    # اطبع كل ما هو محفوظ
    sentiments = client.api.assets_sentiment
    if not sentiments:
        print(f"{Colors.YELLOW}No payout data yet. Type 'assets' first to subscribe.{Colors.RESET}")
        return
    print(f"\n{Colors.BOLD}Payout % (sentiment) — {len(sentiments)} assets:{Colors.RESET}")
    print(f"  {'Asset':<22} {'Payout%':<10}")
    print(f"  {'-'*22} {'-'*10}")
    for name in sorted(sentiments.keys()):
        sent = sentiments[name]
        payout = sent.get("sentiment") if isinstance(sent, dict) else None
        payout_str = f"{payout}%" if payout is not None else "—"
        print(f"  {name:<22} {payout_str:<10}")


async def cmd_prices(client: "Binolla") -> None:
    """يطبع آخر سعر لحظي محفوظ لكل الأصول."""
    if not client.api:
        return
    quotes = client.api.assets_quotes
    if not quotes:
        print(f"{Colors.YELLOW}No quotes yet. Waiting for stream...{Colors.RESET}")
        return
    print(f"\n{Colors.BOLD}Live prices — {len(quotes)} assets:{Colors.RESET}")
    print(f"  {'Asset':<22} {'Price':<20}")
    print(f"  {'-'*22} {'-'*20}")
    for name in sorted(quotes.keys()):
        quote = quotes[name]
        price = None
        if isinstance(quote, dict):
            for k in ("price", "value", "rate", "last"):
                if k in quote:
                    price = quote[k]; break
        elif isinstance(quote, (int, float)):
            price = float(quote)
        price_str = f"{price}" if price is not None else "—"
        print(f"  {name:<22} {price_str:<20}")


async def cmd_candles(client: "Binolla", asset: str, days: int,
                       timeframe: int) -> None:
    """يجلب الشموع التاريخية ويحفظها في JSON."""
    normalized = normalize_asset(asset)
    if not normalized:
        print(f"{Colors.RED}Invalid asset name: {asset}{Colors.RESET}")
        return
    if days <= 0:
        print(f"{Colors.RED}Days must be positive.{Colors.RESET}")
        return
    if timeframe <= 0:
        print(f"{Colors.RED}Timeframe must be positive.{Colors.RESET}")
        return
    print(f"\n{Colors.CYAN}Fetching candles for {normalized} "
          f"({days}d, M{timeframe})...{Colors.RESET}")
    candles = await fetch_candles_for_asset(
        client, normalized, days, timeframe, idx=1, total=1)
    if candles:
        filepath = save_candles_to_json(candles, normalized, timeframe, days)
        print(f"{Colors.GREEN}Saved {len(candles)} candles to: {filepath.absolute()}{Colors.RESET}")
    else:
        print(f"{Colors.RED}No candles fetched for {normalized}.{Colors.RESET}")


async def cmd_watch(live_stream: LivePriceStream,
                     asset_arg: Optional[str] = None) -> None:
    """يضبط بث الأسعار على أصل محدد أو على كل الأصول."""
    if asset_arg:
        asset = asset_arg.strip()
        live_stream.set_watch(asset)
        print(f"{Colors.CYAN}Live stream now watching: {asset}{Colors.RESET}")
    else:
        live_stream.set_watch(None)
        print(f"{Colors.CYAN}Live stream now watching: ALL assets{Colors.RESET}")


async def cmd_prices_live(client: "Binolla", live_stream: LivePriceStream,
                            asset_arg: Optional[str] = None) -> None:
    """يبدأ بث سعر لحظي مستمر لأصل محدد (بعد تأكيد 'ok' من المستخدم).

    الآلية:
    1) يعرض ملخصاً ويطلب تأكيد 'ok' قبل البدء.
    2) يرسل asset/list/change للأصل المطلوب لتفعيل تدفق s_quotes/list الخاص به.
    3) يشترك في sentiment (نسبة الدفع) للأصل.
    4) يضبط LivePriceStream على متابعة هذا الأصل حصرياً.
    5) يستأنف البث إن كان متوقفاً.
    6) السعر يُحدّث على نفس السطر (inline update).

    لإيقاف البث: اكتب 'stop' أو 'watch all' أو 'pause'.
    """
    if not client.api:
        print(f"{Colors.RED}API not connected.{Colors.RESET}")
        return
    if not asset_arg:
        print(f"{Colors.YELLOW}Usage: prices live <asset>{Colors.RESET}")
        print(f"{Colors.DIM}Example: prices live XTIUSD_otc{Colors.RESET}")
        print(f"{Colors.DIM}         prices live EURUSD_otc{Colors.RESET}")
        return
    asset = asset_arg.strip()

    # اطبع معلومات الأصل من قائمة الأصول المحفوظة
    records = _extract_asset_records(client.api.assets_list) if client.api.assets_list else []
    asset_info = next((r for r in records if r.get("asset") == asset), None)
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Live price stream request{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    if asset_info:
        print(f"  Asset:       {asset}")
        print(f"  Name:        {asset_info.get('name', '—')}")
        print(f"  Type:        {asset_info.get('type', '—')}")
        # حالة الأصل (مفتوح/مغلق)
        status_text, status_color = _format_asset_status(asset_info)
        print(f"  Status:      {status_color}{status_text}{Colors.RESET}")
        payout_cached = asset_info.get("payout")
        if payout_cached is not None:
            print(f"  Payout:      {payout_cached}%")
        bid = asset_info.get("bid")
        ask = asset_info.get("ask")
        if bid is not None:
            print(f"  Last bid:    {bid}")
        if ask is not None:
            print(f"  Last ask:    {ask}")
        # تحذير إن كان مغلقاً
        if status_text == "CLOSED":
            print(f"\n  {Colors.RED}WARNING: This asset is currently CLOSED for trading.{Colors.RESET}")
            print(f"  {Colors.DIM}Live prices may still stream, but you cannot place trades.{Colors.RESET}")
    else:
        print(f"  Asset: {asset} (not found in assets list — will try anyway)")

    # اطلب تأكيد 'ok'
    print(f"\n{Colors.YELLOW}Type 'ok' to start live stream, or anything else to cancel.{Colors.RESET}")
    try:
        confirm = (await ainput(f"Confirm [ok]: ")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = ""
    if confirm != "ok":
        print(f"{Colors.YELLOW}Cancelled.{Colors.RESET}")
        return

    print(f"\n{Colors.CYAN}Starting LIVE price stream for: {asset}{Colors.RESET}")
    print(f"{Colors.DIM}Price updates on this line (inline). Type 'stop' to end.{Colors.RESET}")

    # 1) فعّل تدفق quotes للأصل عبر asset/list/change
    try:
        client.api.change_asset(asset, period=60)
        bn_logmsg(f"Sent asset/list/change for {asset} (period=60)")
    except Exception as e:
        bn_logmsg(f"{Colors.YELLOW}change_asset warning: {e}{Colors.RESET}")

    # 2) اشترك في sentiment للأصل
    try:
        client.api.subscribe_asset_sentiment(asset)
        bn_logmsg(f"Subscribed to sentiment for {asset}")
    except Exception as e:
        logger.debug("subscribe_asset_sentiment err: %s", e)

    # 3) اطلب quotes فوراً
    try:
        client.api.subscribe_quotes()
    except Exception as e:
        logger.debug("subscribe_quotes err: %s", e)

    # 4) اضبط البث على هذا الأصل حصرياً + استأنف
    live_stream.set_watch(asset)
    live_stream.resume()
    # اطبع سطر فارغ ليكون هو السطر الذي يُحدّث
    sys.stdout.write("\r\033[K  Waiting for first live quote...\r")
    sys.stdout.flush()


def print_help() -> None:
    """يطبع قائمة الأوامر المتاحة."""
    print(f"\n{Colors.BOLD}Available commands:{Colors.RESET}")
    print(f"  {Colors.CYAN}assets{Colors.RESET}                          Fetch + print all assets with payout% and price")
    print(f"  {Colors.CYAN}payout [asset]{Colors.RESET}                  Print payout% for all (or one) asset")
    print(f"  {Colors.CYAN}prices{Colors.RESET}                           Print current cached live prices (all assets)")
    print(f"  {Colors.CYAN}prices live <asset>{Colors.RESET}             Start continuous live price stream for one asset")
    print(f"  {Colors.DIM}    example: prices live XTIUSD_otc{Colors.RESET}")
    print(f"  {Colors.DIM}             prices live EURUSD_otc{Colors.RESET}")
    print(f"  {Colors.CYAN}stop{Colors.RESET}                            Stop live stream + return to all-assets mode")
    print(f"  {Colors.CYAN}candles <asset> <d> <tf>{Colors.RESET}       Fetch candles (e.g. 'candles EURUSD_otc 7 1')")
    print(f"  {Colors.CYAN}watch <asset>{Colors.RESET}                   Focus live stream on one asset (alias for 'prices live')")
    print(f"  {Colors.CYAN}watch all{Colors.RESET}                       Stream all assets (default)")
    print(f"  {Colors.CYAN}pause{Colors.RESET}                           Pause live price stream")
    print(f"  {Colors.CYAN}resume{Colors.RESET}                          Resume live price stream")
    print(f"  {Colors.CYAN}debug{Colors.RESET}                           Toggle debug mode (print raw WS events)")
    print(f"  {Colors.CYAN}snapshot{Colors.RESET}                         Save JSON snapshot of all assets+payout+price")
    print(f"  {Colors.CYAN}help{Colors.RESET}                            Show this help")
    print(f"  {Colors.CYAN}quit{Colors.RESET}                            Exit")
    print()


async def process_command(cmd_line: str, client: "Binolla",
                            args: Dict[str, Any],
                            live_stream: LivePriceStream) -> bool:
    """يُعالج سطر أمر واحد. يُعيد True لمتابعة الحلقة، False للخروج."""
    parts = cmd_line.strip().split()
    if not parts:
        return True
    cmd = parts[0].lower()
    rest = parts[1:]

    if cmd in ("quit", "exit", "q"):
        return False
    elif cmd == "help" or cmd == "?":
        print_help()
    elif cmd in ("assets", "list", "ls"):
        await cmd_assets(client, live_stream)
    elif cmd == "payout":
        await cmd_payout(client, live_stream, rest[0] if rest else None)
    elif cmd == "prices":
        #prices                 → طباعة كل الأسعار المخزنة
        #prices live <asset>    → بدء بث لحظي مستمر لأصل واحد
        if rest and rest[0].lower() == "live":
            asset_arg = rest[1] if len(rest) > 1 else None
            await cmd_prices_live(client, live_stream, asset_arg)
        else:
            await cmd_prices(client)
    elif cmd == "stop":
        # أوقف بث الأصل الفردي + عُ إلى وضع كل الأصول
        live_stream.set_watch(None)
        live_stream.stop()
        print(f"{Colors.YELLOW}Live stream stopped. Type 'resume' or 'prices live <asset>' to restart.{Colors.RESET}")
    elif cmd == "candles":
        if len(rest) < 3:
            print(f"{Colors.YELLOW}Usage: candles <asset> <days> <timeframe>{Colors.RESET}")
            print(f"{Colors.DIM}Example: candles EURUSD_otc 7 1{Colors.RESET}")
        else:
            try:
                asset = rest[0]
                days = int(rest[1])
                tf = int(rest[2])
                await cmd_candles(client, asset, days, tf)
            except ValueError:
                print(f"{Colors.RED}days and timeframe must be integers.{Colors.RESET}")
    elif cmd == "watch":
        # watch <asset>  →  alias لـ prices live <asset>
        # watch all      →  بث كل الأصول
        if rest and rest[0].lower() == "all":
            live_stream.set_watch(None)
            live_stream.resume()
            print(f"{Colors.CYAN}Live stream now watching: ALL assets{Colors.RESET}")
        elif rest:
            await cmd_prices_live(client, live_stream, rest[0])
        else:
            print(f"{Colors.YELLOW}Usage: watch <asset>  or  watch all{Colors.RESET}")
    elif cmd == "pause":
        live_stream.stop()
        print(f"{Colors.YELLOW}Live price stream paused.{Colors.RESET}")
    elif cmd == "resume":
        live_stream.resume()
        print(f"{Colors.GREEN}Live price stream resumed.{Colors.RESET}")
    elif cmd == "debug":
        if rest and rest[0].lower() in ("off", "0", "false", "no"):
            live_stream.set_debug(False)
            print(f"{Colors.YELLOW}Debug mode OFF.{Colors.RESET}")
        else:
            live_stream.set_debug(True)
            print(f"{Colors.GREEN}Debug mode ON — will print raw s_quotes/list, "
                  f"s_history/last, s_asset/sentiment events as they arrive.{Colors.RESET}")
            print(f"{Colors.DIM}Type 'debug off' to disable.{Colors.RESET}")
    elif cmd == "snapshot":
        if client.api and (client.api.assets_sentiment or client.api.assets_quotes):
            snapshot = await fetch_all_assets_info(client, wait_seconds=0.5)
            if "error" not in snapshot:
                out = save_assets_info_to_json(snapshot)
                print(f"{Colors.GREEN}Snapshot saved to: {out.absolute()}{Colors.RESET}")
            else:
                print(f"{Colors.RED}Snapshot error: {snapshot['error']}{Colors.RESET}")
        else:
            print(f"{Colors.YELLOW}No data to snapshot yet.{Colors.RESET}")
    else:
        print(f"{Colors.RED}Unknown command: {cmd}{Colors.RESET}")
        print(f"{Colors.DIM}Type 'help' for available commands.{Colors.RESET}")
    return True


# ==============================================================================
# SECTION 15: MAIN LOOP (continuous stream + interactive commands)
# ==============================================================================

# ==============================================================================
# DUAL SERVER — Unified HTTP API + CLI (separate per broker, NOT merged)
# ==============================================================================
import os
import sys
import json
import time
import asyncio
import sqlite3
import threading
import argparse
import logging as _dual_logging
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any, Tuple
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

SERVER_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(SERVER_DIR))

_dual_logging.basicConfig(
    level=_dual_logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        _dual_logging.FileHandler(SERVER_DIR / "dual_server.log", encoding="utf-8"),
        _dual_logging.StreamHandler(sys.stdout),
    ],
)
logger = _dual_logging.getLogger("DualServer")
_dual_logging.getLogger("werkzeug").setLevel(_dual_logging.ERROR)

DB_PATH = SERVER_DIR / "dual_server.db"
CREDS_FILE = SERVER_DIR / "credentials.json"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS candles (
        platform TEXT, asset TEXT, timeframe INTEGER, time INTEGER,
        open REAL, high REAL, low REAL, close REAL,
        PRIMARY KEY (platform, asset, timeframe, time))""")
    c.execute("""CREATE TABLE IF NOT EXISTS payouts (
        platform TEXT, asset TEXT, payout REAL, display_name TEXT,
        open INTEGER, updated_at TEXT,
        PRIMARY KEY (platform, asset))""")
    conn.commit()
    conn.close()
    logger.info(f"Database initialized at {DB_PATH}")


# ==============================================================================
# QUOTEX PAYOUTS CAPTURE (monkey-patch + binary frame handler)
# ==============================================================================
_QX_PAYOUTS: Dict[str, Dict] = {}
_QX_PAYOUTS_LOCK = threading.RLock()
_QX_PAYOUTS_LAST_UPDATE = 0.0
_QX_BINARY_PENDING: Dict = {"event": None, "json": None, "num": 0, "buffers": []}


def _qx_parse_payouts(message) -> Dict[str, Dict]:
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
            if name: name = name.replace("\n", "").strip()
            p = item[5] if len(item) > 5 else None
            is_open = item[14] if len(item) > 14 else None
            dn = str(item[2]).replace("\n", " ").strip() if len(item) > 2 and item[2] else name
            if name and p is not None:
                try:
                    return name, {"payout": float(p)*100 if float(p)<=1 else float(p),
                                  "display_name": dn,
                                  "open": bool(is_open) if is_open is not None else None}
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
    WSC = WebsocketClient
    orig = WSC.on_message

    def patched(self, wss, msg):
        if isinstance(msg, (bytes, bytearray)):
            mb = bytes(msg)
            pending = _QX_BINARY_PENDING.get("event", "")
            if pending:
                _QX_BINARY_PENDING.update({"event": None, "json": None, "num": 0, "buffers": []})
            if len(mb) > 0 and mb[0] == 0x04:
                try:
                    ps = mb[1:].decode("utf-8", errors="ignore")
                    parsed = json.loads(ps)
                    if pending and any(x in pending.lower() for x in ("instruments", "assets", "settings")):
                        _qx_on_instruments(parsed)
                except: pass
            try: orig(self, wss, msg)
            except: pass
            return
        try:
            if isinstance(msg, str):
                ms = msg
                if ms not in ("2", "3", "41"):
                    if ms.startswith("45") and "-" in ms[:6]:
                        try:
                            d = ms.index("-", 2)
                            n = int(ms[2:d])
                            p = json.loads(ms[d+1:])
                            if isinstance(p, list) and p:
                                ev = str(p[0]).lower()
                                if any(x in ev for x in ("instruments", "assets", "settings")):
                                    _QX_BINARY_PENDING.update({"event": p[0], "json": p, "num": n, "buffers": []})
                        except: pass
                    elif ms.startswith("42["):
                        try:
                            p = json.loads(ms[2:])
                            if isinstance(p, list) and len(p) >= 2:
                                ev = str(p[0]).lower()
                                if any(x in ev for x in ("instruments", "assets", "settings")):
                                    payload = p[1]
                                    if isinstance(payload, dict) and not payload.get("_placeholder"):
                                        _qx_on_instruments(payload)
                        except: pass
        except: pass
        try: orig(self, wss, msg)
        except: pass

    WSC.on_message = patched
    logger.info("[Quotex] Payouts capture hook installed")


# ==============================================================================
# QUOTEX MANAGER
# ==============================================================================
class QuotexManager:
    def __init__(self, email, password):
        self.email = email
        self.password = password
        self._bg = False

    async def connect(self):
        _qx_install_hook()
        logger.info(f"[Quotex] Connecting as {self.email}...")
        loop = globals().get("ASYNC_LOOP")
        if not loop or not loop.is_running():
            # Start the async engine if not running
            global ASYNC_LOOP
            if ASYNC_LOOP is None or not ASYNC_LOOP.is_running():
                logger.error("[Quotex] ASYNC_LOOP not running")
                return False
        future = asyncio.run_coroutine_threadsafe(
            connect_quotex(self.email, self.password, force_fresh=True, max_attempts=3),
            ASYNC_LOOP)
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
        self._schedule_bg()
        return True

    def _schedule_bg(self):
        if self._bg:
            return
        if not ASYNC_LOOP or not ASYNC_LOOP.is_running():
            return
        try:
            asyncio.run_coroutine_threadsafe(keepalive_loop(), ASYNC_LOOP)
            asyncio.run_coroutine_threadsafe(auto_reconnect(), ASYNC_LOOP)
            asyncio.run_coroutine_threadsafe(stale_message_watchdog(), ASYNC_LOOP)
            asyncio.run_coroutine_threadsafe(health_monitor(), ASYNC_LOOP)
            self._bg = True
            logger.info("[Quotex] Background tasks scheduled")
        except Exception as exc:
            logger.error(f"[Quotex] BG tasks failed: {exc}")

    def is_alive(self):
        return bool(CONNECTION_ALIVE and CLIENT and CLIENT.api and
                     getattr(CLIENT.api.state, "check_accepted_connection", False))

    def get_payouts(self):
        with _QX_PAYOUTS_LOCK:
            return dict(_QX_PAYOUTS)

    def get_payout(self, asset):
        with _QX_PAYOUTS_LOCK:
            return _QX_PAYOUTS.get(asset)

    def start_stream(self, asset):
        if not self.is_alive():
            return False
        global PERIOD, PERIOD_SECONDS
        PERIOD = 1
        PERIOD_SECONDS = 60
        for a in ALL_STREAMING_ASSETS:
            if a.api_symbol == asset and a.streaming:
                return True
        try:
            obj = Asset(asset)
        except:
            return False
        if obj not in ALL_STREAMING_ASSETS:
            ALL_STREAMING_ASSETS.append(obj)
        try:
            obj.stream_task = asyncio.run_coroutine_threadsafe(realtime_stream(obj), ASYNC_LOOP)
            logger.info(f"[Quotex] Stream started for {asset}")
            return True
        except:
            return False

    def get_live_price(self, asset):
        for a in ALL_STREAMING_ASSETS:
            if a.api_symbol == asset and a.price > 0:
                try: digits = a.digits(a.price)
                except: digits = 5
                return {"price": float(a.price), "time": int(a.last_update_time or 0), "digits": digits}
        return None

    def get_streaming_assets(self):
        return [a.api_symbol for a in ALL_STREAMING_ASSETS if a.streaming]

    def status(self):
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
    def __init__(self, email, password, is_demo=True):
        self.email = email
        self.password = password
        self.is_demo = is_demo
        self.client = None
        self._stop = None
        self._tasks = []

    async def connect(self):
        logger.info(f"[Binolla] Logging in as {self.email}...")
        args = {"email": self.email, "password": self.password, "is_demo": self.is_demo}
        token = await auto_login(args)
        if not token:
            logger.error("[Binolla] Login failed")
            return False
        logger.info("[Binolla] JWT obtained, connecting WebSocket...")
        self.client = await connect_binolla(token, is_demo=self.is_demo, max_attempts=3)
        if not self.client:
            logger.error("[Binolla] WS connection failed")
            return False
        logger.info("[Binolla] Connected successfully")
        self._stop = asyncio.Event()
        self._tasks.append(asyncio.create_task(keepalive_loop(self.client, self._stop)))
        self._tasks.append(asyncio.create_task(jwt_refresh_loop(self.client, args, self._stop)))
        self._tasks.append(asyncio.create_task(watchdog_reconnect_loop(self.client, args, self._stop)))
        logger.info("[Binolla] Background tasks started")
        return True

    def is_alive(self):
        return bool(self.client and self.client.api and
                     getattr(self.client.api.state, "check_accepted_connection", False))

    def get_payouts(self):
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

    def get_payout(self, asset):
        return self.get_payouts().get(asset)

    def get_live_price(self, asset):
        if not self.client or not self.client.api:
            return None
        q = self.client.api.assets_quotes.get(asset)
        if q and isinstance(q, dict):
            return {"price": float(q.get("price", 0)), "time": int(q.get("time", 0)), "digits": 5}
        return None

    def get_streaming_assets(self):
        if not self.client or not self.client.api:
            return []
        return list(self.client.api.assets_quotes.keys())

    def status(self):
        return {
            "connected": self.is_alive(),
            "email": self.email,
            "payouts_count": len(self.get_payouts()),
            "streaming_count": len(self.get_streaming_assets()),
        }


# ==============================================================================
# HTTP API SERVER (SEPARATE per broker — NOT merged)
# ==============================================================================
class DualHandler(BaseHTTPRequestHandler):
    qx_mgr = None
    bn_mgr = None

    def _h(self, s=200):
        self.send_response(s)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    def _j(self, data, s=200):
        self._h(s)
        self.wfile.write(json.dumps(data, ensure_ascii=False, default=str).encode("utf-8"))

    def _e(self, msg, s=400):
        self._j({"error": msg}, s)

    def do_OPTIONS(self):
        self._h(200)

    def do_GET(self):
        p = urlparse(self.path)
        path = p.path.rstrip("/") or "/"
        params = parse_qs(p.query)

        if path == "/api/health":
            self._j({"status": "ok", "time": datetime.now(timezone.utc).isoformat(),
                     "quotex": self.qx_mgr.is_alive() if self.qx_mgr else False,
                     "binolla": self.bn_mgr.is_alive() if self.bn_mgr else False})
            return
        if path == "/api/status":
            self._j({"quotex": self.qx_mgr.status() if self.qx_mgr else {},
                     "binolla": self.bn_mgr.status() if self.bn_mgr else {}})
            return

        # QUOTEX (separate endpoints)
        if path == "/api/quotex/payouts":
            self._j({"platform": "quotex", "count": len(self.qx_mgr.get_payouts()),
                     "payouts": self.qx_mgr.get_payouts()})
            return
        if path.startswith("/api/quotex/payouts/"):
            a = path.replace("/api/quotex/payouts/", "")
            info = self.qx_mgr.get_payout(a)
            self._j({"platform": "quotex", "asset": a, **(info or {})}) if info else self._e(f"Not found: {a}", 404)
            return
        if path == "/api/quotex/streaming":
            self._j({"platform": "quotex", "assets": self.qx_mgr.get_streaming_assets()})
            return
        if path == "/api/quotex/last-tick":
            a = params.get("asset", [None])[0]
            if not a: self._e("Missing asset"); return
            live = self.qx_mgr.get_live_price(a)
            self._j({"platform": "quotex", "asset": a, "status": "OK" if live else "WAIT", **(live or {})})
            return

        # BINOLLA (separate endpoints)
        if path == "/api/binolla/payouts":
            self._j({"platform": "binolla", "count": len(self.bn_mgr.get_payouts()),
                     "payouts": self.bn_mgr.get_payouts()})
            return
        if path.startswith("/api/binolla/payouts/"):
            a = path.replace("/api/binolla/payouts/", "")
            info = self.bn_mgr.get_payout(a)
            self._j({"platform": "binolla", "asset": a, **(info or {})}) if info else self._e(f"Not found: {a}", 404)
            return
        if path == "/api/binolla/streaming":
            self._j({"platform": "binolla", "assets": self.bn_mgr.get_streaming_assets()})
            return
        if path == "/api/binolla/last-tick":
            a = params.get("asset", [None])[0]
            if not a: self._e("Missing asset"); return
            live = self.bn_mgr.get_live_price(a)
            self._j({"platform": "binolla", "asset": a, "status": "OK" if live else "WAIT", **(live or {})})
            return

        self._e("Not found", 404)

    def log_message(self, *a):
        pass


def make_handler(qx, bn):
    class H(DualHandler): pass
    H.qx_mgr = qx
    H.bn_mgr = bn
    return H


# ==============================================================================
# CLI (separate per broker)
# ==============================================================================
class DualCLI:
    def __init__(self, qx, bn):
        self.qx = qx
        self.bn = bn

    def run(self):
        print("\n" + "=" * 60)
        print("DualServer CLI (Quotex + Binolla — SEPARATE assets)")
        print("=" * 60)
        print("Commands: status | qx assets | qx payout [a] | qx watch <a>")
        print("          bn assets | bn payout [a] | bn streaming")
        print("          qx streaming | help | quit\n")
        while True:
            try:
                line = input("dual> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\nExiting..."); break
            if not line: continue
            parts = line.split()
            cmd = parts[0].lower()
            args = parts[1:]
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                self._help()
            elif cmd == "status":
                self._status()
            elif cmd == "qx":
                self._qx(args)
            elif cmd == "bn":
                self._bn(args)
            else:
                print(f"Unknown: {cmd}. Type 'help'.")

    def _help(self):
        print("status              — both platforms status")
        print("qx assets           — Quotex assets (payout% + open/closed)")
        print("qx payout [asset]   — Quotex payout for all or one")
        print("qx watch <asset>    — start Quotex live stream")
        print("qx streaming        — Quotex streaming assets + prices")
        print("bn assets           — Binolla assets (payout% + price)")
        print("bn payout [asset]   — Binolla payout for all or one")
        print("bn streaming        — Binolla streaming assets + prices")
        print("quit                — exit")

    def _status(self):
        qs = self.qx.status()
        bs = self.bn.status()
        print(f"\n--- Quotex ---    --- Binolla ---")
        print(f"Connected: {qs['connected']!s:<5}      Connected: {bs['connected']!s:<5}")
        print(f"Payouts:   {qs['payouts_count']:<5}      Payouts:   {bs['payouts_count']:<5}")
        print(f"Streaming: {qs['streaming_count']:<5}      Streaming: {bs['streaming_count']:<5}")

    def _qx(self, args):
        if not args: print("Usage: qx <assets|payout|watch|streaming>"); return
        sub = args[0].lower()
        if sub == "assets":
            p = self.qx.get_payouts()
            if not p: print("[Quotex] No assets. Wait for refresh."); return
            print(f"\n{'#':<4} {'DISPLAY':<24} {'SYMBOL':<16} {'PAYOUT':<8} {'STATUS'}")
            print("-" * 65)
            for i, (name, info) in enumerate(sorted(p.items()), 1):
                payout = info.get("payout", 0)
                dn = info.get("display_name", name)
                is_open = info.get("open")
                st = "OPEN" if is_open else ("CLOSED" if is_open is False else "-")
                print(f"{i:<4} {dn[:24]:<24} {name:<16} {payout:5.1f}%  {st}")
            print(f"\nTotal: {len(p)} Quotex assets")
        elif sub == "payout":
            if len(args) > 1:
                info = self.qx.get_payout(args[1])
                if info: print(f"[Quotex] {args[1]}: {info.get('payout', 0):.1f}%")
                else: print(f"[Quotex] No payout for {args[1]}")
            else:
                p = self.qx.get_payouts()
                for name, info in sorted(p.items()):
                    print(f"  {name:<20} {info.get('payout', 0):5.1f}%")
                print(f"\nTotal: {len(p)} Quotex assets")
        elif sub == "watch":
            if len(args) < 2: print("Usage: qx watch <asset>"); return
            if self.qx.start_stream(args[1]):
                print(f"[Quotex] Streaming: {args[1]}")
            else:
                print(f"[Quotex] Failed: {args[1]}")
        elif sub == "streaming":
            assets = self.qx.get_streaming_assets()
            if not assets: print("[Quotex] No streams"); return
            for a in assets:
                live = self.qx.get_live_price(a)
                if live: print(f"  {a:<20} {live['price']:.{live['digits']}f}")
                else: print(f"  {a:<20} (waiting)")
            print(f"\nTotal: {len(assets)} Quotex streams")

    def _bn(self, args):
        if not args: print("Usage: bn <assets|payout|streaming>"); return
        sub = args[0].lower()
        if sub in ("assets", "payout"):
            p = self.bn.get_payouts()
            if not p: print("[Binolla] No payout data."); return
            for name, info in sorted(p.items()):
                print(f"  {name:<20} {info.get('payout', 0)}%")
            print(f"\nTotal: {len(p)} Binolla assets")
        elif sub == "streaming":
            assets = self.bn.get_streaming_assets()
            if not assets: print("[Binolla] No streams"); return
            for a in assets:
                live = self.bn.get_live_price(a)
                if live: print(f"  {a:<20} {live['price']:.5f}")
                else: print(f"  {a:<20} (waiting)")
            print(f"\nTotal: {len(assets)} Binolla streams")


# ==============================================================================
# MAIN
# ==============================================================================
def load_creds():
    if CREDS_FILE.exists():
        try: return json.loads(CREDS_FILE.read_text())
        except: pass
    return {}

def save_creds(c):
    try: CREDS_FILE.write_text(json.dumps(c, indent=2))
    except: pass

async def server_main(qx_email, qx_pass, bn_email, bn_pass, bn_demo, port, host):
    init_db()
    qx_mgr = QuotexManager(qx_email, qx_pass)
    bn_mgr = BinollaManager(bn_email, bn_pass, is_demo=bn_demo)

    logger.info("=" * 60)
    logger.info("Connecting to Quotex...")
    qx_ok = await qx_mgr.connect()
    if not qx_ok:
        logger.warning("Quotex failed — continuing with Binolla")

    logger.info("Connecting to Binolla (Quotex stays alive)...")
    bn_ok = await bn_mgr.connect()
    if not bn_ok:
        logger.warning("Binolla failed — continuing with Quotex")

    save_creds({"quotex": {"email": qx_email, "password": qx_pass},
                "binolla": {"email": bn_email, "password": bn_pass, "is_demo": bn_demo}})

    handler = make_handler(qx_mgr, bn_mgr)
    httpd = ThreadingHTTPServer((host, port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    logger.info("=" * 60)
    logger.info(f"DualServer on http://{host}:{port}")
    logger.info("  /api/quotex/payouts        — Quotex payouts (separate)")
    logger.info("  /api/quotex/last-tick      — Quotex live prices")
    logger.info("  /api/binolla/payouts       — Binolla payouts (separate)")
    logger.info("  /api/binolla/last-tick     — Binolla live prices")
    logger.info("  /api/health | /api/status  — both platforms")
    logger.info("=" * 60)

    cli = DualCLI(qx_mgr, bn_mgr)
    threading.Thread(target=cli.run, daemon=True, name="CLI").start()

    try:
        while True:
            await asyncio.sleep(3600)
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Shutting down...")
        httpd.shutdown()

def main():
    parser = argparse.ArgumentParser(description="DualServer — Quotex + Binolla (single file)")
    parser.add_argument("--qx-email", help="Quotex email")
    parser.add_argument("--qx-password", help="Quotex password")
    parser.add_argument("--bn-email", help="Binolla email")
    parser.add_argument("--bn-password", help="Binolla password")
    parser.add_argument("--bn-real", action="store_true", help="Binolla real account")
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    creds = load_creds()
    qc = creds.get("quotex", {})
    bc = creds.get("binolla", {})
    qx_email = args.qx_email or qc.get("email", "")
    qx_pass = args.qx_password or qc.get("password", "")
    bn_email = args.bn_email or bc.get("email", "")
    bn_pass = args.bn_password or bc.get("password", "")
    bn_demo = not args.bn_real if args.bn_real else bc.get("is_demo", True)

    if not all([qx_email, qx_pass, bn_email, bn_pass]):
        print("Usage: python DualServer.py --qx-email X --qx-password Y --bn-email Z --bn-password W")
        sys.exit(1)

    try:
        asyncio.run(server_main(qx_email, qx_pass, bn_email, bn_pass, bn_demo, args.port, args.host))
    except KeyboardInterrupt:
        print("\nStopped")

if __name__ == "__main__":
    main()
