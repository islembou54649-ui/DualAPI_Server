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
HOST = "binolla.com"
WS_HOST = "ws3.binolla.com"
ORIGIN_URL = f"https://{HOST}"
WSS_URL = f"wss://{WS_HOST}/socket.io/?EIO=4&transport=websocket"

USER_AGENT = (
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

CREDENTIALS_FILE = Path("credentials.json")
DATA_DIR = Path("binolla_data")
DATA_DIR.mkdir(exist_ok=True)
LOG_FILE = Path("binolla.log")

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


def logmsg(msg: str) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    # إن كان البث اللحظي نشطاً، اطبع على سطر جديد أولاً لتفادي الكتابة فوق السعر
    if _LIVE_STREAM_ACTIVE:
        sys.stdout.write("\n")
    print(f"  \033[2m[{ts}]\033[0m {msg}")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] {msg}\n")
    except Exception:
        pass


def log_exception(context: str, exc: BaseException) -> None:
    ts = datetime.now().strftime("%H:%M:%S")
    tb_text = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
    print(f"  \033[91m[{ts}] FATAL in {context}: {exc}\033[0m")
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] FATAL in {context}: {exc}\n{tb_text}\n")
    except Exception:
        pass


# إعداد سكّت WebSocket
def _prepare_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s | %(message)s",
        datefmt="%H:%M:%S",
    )
    ws_logger = logging.getLogger("websocket")
    ws_logger.setLevel(logging.WARNING)
    ws_logger.addHandler(logging.NullHandler())


_prepare_logging()
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
    log_exception(f"thread '{args.thread.name}'", args.exc_value)
threading.excepthook = _thread_excepthook


def _main_excepthook(exc_type, exc_value, exc_tb):
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_tb)
        return
    log_exception("main thread (top level)", exc_value)
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
            logmsg(f"{Colors.CYAN}WS message log: {BinollaWebsocketClient._ws_log_path.absolute()}{Colors.RESET}")
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
        logmsg(f"WebSocket channel opened to {WS_HOST}")
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
            log_exception("on_message", e)
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
        logmsg(f"Engine.IO session established (sid={sid[:8]}..., "
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
            logmsg(f"{Colors.GREEN}Authorization accepted.{Colors.RESET}")
            self.state.check_accepted_connection = True
            self.state.check_rejected_connection = False
            self.state.auth_status = AuthStatus.AUTHENTICATED
            self.state.status = WebsocketStatus.CONNECTED
            self.state.signal_auth_accepted()
            # بعد التأكيد، نُشترك في كل القنوات
            self._send_post_auth_subscriptions()
        elif event_name == "authorization/reject":
            logger.warning("Authorization REJECTED by server.")
            logmsg(f"{Colors.RED}Authorization rejected.{Colors.RESET}")
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
            logmsg(f"{Colors.RED}No JWT token available — cannot authorize.{Colors.RESET}")
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
            logmsg("Sent authorization frame to Binolla server...")
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
        log_exception("websocket.on_error", error if isinstance(error, BaseException)
                      else RuntimeError(str(error)))
        self.state.websocket_error_reason = str(error)
        self.state.check_websocket_if_error = True
        self.state.status = WebsocketStatus.ERROR
        self.state.check_accepted_connection = False
        self.state.signal_ws_error()

    def on_close(self, wss, close_status_code, close_msg):
        logger.info("WebSocket closed: code=%s msg=%s", close_status_code, close_msg)
        logmsg(f"WebSocket closed (code={close_status_code}).")
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
    if not CREDENTIALS_FILE.exists():
        return None
    try:
        data = json.loads(CREDENTIALS_FILE.read_text())
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
        if CREDENTIALS_FILE.exists():
            try:
                existing = json.loads(CREDENTIALS_FILE.read_text())
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
        CREDENTIALS_FILE.write_text(json.dumps(existing, indent=2))
        return True
    except Exception as e:
        logmsg(f"Failed to save credentials: {e}")
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
    base_url = HOST
    https_base_url = ORIGIN_URL
    login_url = f"{ORIGIN_URL}/login"

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
        logmsg(f"GET /login — CSRF token: {'found' if csrf else 'none'}")

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
            logmsg(f"Trying POST (form) {ep} ...")
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
                logmsg(f"Trying POST (JSON) {ep} ...")
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
        logmsg("No candles to save.")
        return None
    try:
        rnd = random.randint(1000, 9999)
        filename = f"{asset}_{timeframe_min}m_{days}d_{rnd}.json"
        filepath = DATA_DIR / filename
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
        log_exception("save_candles_to_json", e)
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
        logmsg(f"Connecting to Binolla (attempt {attempt}/{max_attempts})...")
        client = Binolla(token=token, is_demo=is_demo, proxies=proxies)
        try:
            ok, reason = await asyncio.wait_for(client.connect(), timeout=30)
            if ok:
                logmsg(f"{Colors.GREEN}Connected to Binolla (account={'demo' if is_demo else 'real'}).{Colors.RESET}")
                return client
            logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} failed: {reason}{Colors.RESET}")
        except asyncio.TimeoutError:
            logmsg(f"{Colors.YELLOW}Attempt {attempt}/{max_attempts} timed out.{Colors.RESET}")
            try:
                await client.close()
            except Exception:
                pass
        except Exception as e:
            log_exception(f"connect_binolla#{attempt}", e)
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
        logmsg(f"{Colors.YELLOW}JWT expires in {remaining:.0f}s — refreshing via HTTP login...{Colors.RESET}")
        new_token = await _http_login(args)
        if not new_token:
            logmsg(f"{Colors.RED}JWT refresh failed — will retry in {check_interval:.0f}s.{Colors.RESET}")
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
            logmsg(f"{Colors.GREEN}JWT refreshed. New expiry: "
                   f"{datetime.fromtimestamp(exp_new).strftime('%H:%M:%S')}{Colors.RESET}")
        else:
            logmsg(f"{Colors.GREEN}JWT refreshed.{Colors.RESET}")


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
        logmsg(f"{Colors.YELLOW}Watchdog: connection dead (connected={connected}, "
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
            logmsg(f"{Colors.CYAN}Watchdog: refreshing JWT before reconnect...{Colors.RESET}")
            new_token = await _http_login(args)
            if not new_token:
                logmsg(f"{Colors.RED}Watchdog: refresh failed. Will retry in {check_interval:.0f}s.{Colors.RESET}")
                continue
            current_token = new_token
            client.api.token = new_token
            client.api.state.SSID = new_token
            client.token = new_token

        # أعد بناء الاتصال (حتى 5 محاولات)
        reconnected = False
        for attempt in range(1, max_reconnect_attempts + 1):
            logmsg(f"{Colors.CYAN}Watchdog: reconnect attempt {attempt}/{max_reconnect_attempts}...{Colors.RESET}")
            try:
                ok, reason = await asyncio.wait_for(client.connect(), timeout=30)
                if ok:
                    logmsg(f"{Colors.GREEN}Watchdog: reconnected successfully (attempt {attempt}).{Colors.RESET}")
                    # أعد الاشتراكات بعد نجاح إعادة الاتصال
                    try:
                        client.api.restore_subscriptions()
                        logmsg(f"{Colors.GREEN}Subscriptions restored after reconnect.{Colors.RESET}")
                    except Exception as e:
                        logger.error("Error restoring subscriptions: %s", e)
                    reconnected = True
                    break
                else:
                    logmsg(f"{Colors.RED}Watchdog: reconnect failed: {reason}{Colors.RESET}")
            except asyncio.TimeoutError:
                logmsg(f"{Colors.RED}Watchdog: reconnect timed out (attempt {attempt}).{Colors.RESET}")
            except Exception as e:
                logmsg(f"{Colors.RED}Watchdog: reconnect error (attempt {attempt}): {e}{Colors.RESET}")
            # فاصل متزايد: 1s, 2s, 4s, 8s, 16s
            if attempt < max_reconnect_attempts:
                delay = 2 ** (attempt - 1)
                logmsg(f"Retrying in {delay}s...")
                await asyncio.sleep(delay)
        if not reconnected:
            logmsg(f"{Colors.RED}Watchdog: all {max_reconnect_attempts} reconnect attempts failed.{Colors.RESET}")
            logmsg(f"Will retry in {check_interval:.0f}s...")


async def fetch_candles_for_asset(client: Binolla, asset: str, days: int,
                                    timeframe_min: int, idx: int = 1,
                                    total: int = 1) -> List[Dict]:
    display = pretty_asset(asset, timeframe_min)
    logmsg(f"[{idx}/{total}] Fetching candles for {display} ({days} days, M{timeframe_min})...")

    MAX_RETRIES = MAX_FETCH_RETRIES
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            if not client.api or not client.api.state.check_accepted_connection:
                logmsg(f"Connection dead before attempt {attempt}; aborting.")
                return []
            candles = await asyncio.wait_for(
                client.fetch_candles(asset, days, timeframe_min, timeout=30),
                timeout=45,
            )
            if candles:
                logmsg(f"{Colors.GREEN}Got {len(candles)} candles.{Colors.RESET}")
                return candles
            logmsg(f"Attempt {attempt}/{MAX_RETRIES}: empty response.")
        except asyncio.TimeoutError:
            logmsg(f"Attempt {attempt}/{MAX_RETRIES}: fetch timed out.")
        except Exception as e:
            logmsg(f"Attempt {attempt}/{MAX_RETRIES} raised: {e}")
        if attempt < MAX_RETRIES:
            delay = min(RETRY_BACKOFF_BASE ** attempt, RETRY_BACKOFF_MAX)
            logmsg(f"Retry in {delay:.1f}s...")
            await asyncio.sleep(delay)
    logmsg(f"All {MAX_RETRIES} attempts failed for {display}")
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
        logmsg(f"{Colors.GREEN}Using CLI-provided JWT (still valid).{Colors.RESET}")
        return token

    # 2) حمّل credentials.json
    creds = load_credentials()
    if creds:
        if creds.get("token") and not is_token_expired(creds["token"]):
            logmsg(f"{Colors.GREEN}Using saved JWT from credentials.json (still valid).{Colors.RESET}")
            # املأ email/password من الاعتمادات المحفوظة لاستخدامها لاحقاً عند انتهاء الصلاحية
            if not email and creds.get("email"):
                args["email"] = creds["email"]
            if not password and creds.get("password"):
                args["password"] = creds["password"]
            return creds["token"]

        # الـ JWT منتهٍ — جرّب إعادة الدخول عبر email/password
        if creds.get("email") and creds.get("password"):
            logmsg(f"{Colors.YELLOW}Saved JWT expired — re-logging in via HTTP...{Colors.RESET}")
            args["email"] = creds["email"]
            args["password"] = creds["password"]
            return await _http_login(args)

    # 3) إن وُجد email/password من CLI/env — سجّل الدخول
    if email and password:
        logmsg(f"Logging in as {email} via HTTP (qx__1.py-style)...")
        return await _http_login(args)

    # 4) لا اعتمادات على الإطلاق — اطلب email/password من المستخدم (مرة واحدة)
    logmsg(f"{Colors.CYAN}No credentials found. First-time setup:{Colors.RESET}")
    print(f"{Colors.DIM}  Enter your Binolla account email and password.{Colors.RESET}")
    print(f"{Colors.DIM}  They will be saved to {CREDENTIALS_FILE.name} so you won't be asked again.{Colors.RESET}")
    email_in, password_in = await prompt_email_password()
    if not email_in or not password_in:
        logmsg(f"{Colors.RED}Email and password are required. Exiting.{Colors.RESET}")
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
    print(f"{Colors.GREEN}Credentials saved to {CREDENTIALS_FILE.name}{Colors.RESET}")
    logmsg(f"Logging in as {email_in} via HTTP (qx__1.py-style)...")
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
        logmsg(f"{Colors.RED}HTTP login exception: {e}{Colors.RESET}")
        return None
    if not ok:
        logmsg(f"{Colors.RED}HTTP login failed: {jwt_or_err}{Colors.RESET}")
        logmsg(f"{Colors.YELLOW}Hint: Binolla uses Cloudflare Turnstile on /login. "
               f"Try logging in via browser once and copy the JWT from DevTools → "
               f"Application → Local Storage → 'token' key.{Colors.RESET}")
        return None
    logmsg(f"{Colors.GREEN}Got JWT from HTTP login.{Colors.RESET}")
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
        out_path = DATA_DIR / f"assets_info_{ts}.json"
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
    logmsg(f"{Colors.CYAN}Requesting assets/list...{Colors.RESET}")
    await api.event_registry.clear_event("s_assets/list")
    api.fetch_assets()
    assets_payload = await api.event_registry.wait_event(
        "s_assets/list", timeout=10.0)
    if not assets_payload:
        # ربما وصلت تلقائياً بعد المصادقة
        assets_payload = api.assets_list
    if not assets_payload:
        logmsg(f"{Colors.RED}No assets/list received.{Colors.RESET}")
        return {"error": "no assets/list", "assets": []}

    api.assets_list = assets_payload
    asset_names = _extract_asset_names(assets_payload)
    logmsg(f"{Colors.GREEN}Got {len(asset_names)} assets.{Colors.RESET}")
    logger.debug("First 10 assets: %s", asset_names[:10])

    # 2) اشترك في sentiment العام (يصل لكل الأصول تدريجياً)
    logmsg(f"{Colors.CYAN}Subscribing to global sentiment (s_asset/sentiment)...{Colors.RESET}")
    api.subscribe_global_sentiment()

    # 3) لكل أصل، اشترك في sentiment + quotes + signals
    #    نرسل بشكل دفعي لكن بفاصل قصير لتفادي الـ rate-limiting.
    logmsg(f"{Colors.CYAN}Subscribing per-asset sentiment + quotes + signals "
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
    logmsg(f"{Colors.CYAN}Waiting {wait_seconds:.1f}s to collect sentiment + quotes...{Colors.RESET}")
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
        logmsg(f"Sent asset/list/change for {asset} (period=60)")
    except Exception as e:
        logmsg(f"{Colors.YELLOW}change_asset warning: {e}{Colors.RESET}")

    # 2) اشترك في sentiment للأصل
    try:
        client.api.subscribe_asset_sentiment(asset)
        logmsg(f"Subscribed to sentiment for {asset}")
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
async def main_async():
    """التدفق الرئيسي — بث مستمر + أوامر تفاعلية:

    1) يحمّل credentials.json تلقائياً (الإيميل + كلمة السر)
    2) يسجّل الدخول عبر HTTP email/password
    3) يتصل مباشرة بحساب DEMO
    4) يشغّل 3 مهام خلفية متوازية:
       a) keepalive_loop: يرسل quotes/list كل 3 ثوانٍ (يجلب الأسعار + يبقي السيرفر نشطاً)
       b) jwt_refresh_loop: يحدّث JWT قبل انتهائه بـ 120 ثانية (لا حاجة لإعادة الاتصال)
       c) watchdog_reconnect_loop: يعيد الاتصال تلقائياً عند الانقطاع
    5) يشغّل LivePriceStream الذي يطبع الأسعار فور وصولها (event-driven)
    6) يعرض قائمة أوامر تفاعلية: assets, payout, prices, candles, watch, etc.
    7) لا ينتهي إلا بـ 'quit' أو Ctrl+C
    """
    args = parse_args()
    print_banner()

    # ===== 1) تسجيل دخول تلقائي (الإيميل + كلمة السر فقط) =====
    args["is_demo"] = not (args.get("is_demo") is False)
    logmsg(f"{Colors.CYAN}Auto-login: loading credentials.json (email + password)...{Colors.RESET}")
    token = await auto_login(args)
    if not token:
        logmsg(f"{Colors.RED}Cannot proceed without a valid JWT. Exiting.{Colors.RESET}")
        return

    email = args.get("email", "")
    password = args.get("password", "")

    # تحقق نهائي
    if is_token_expired(token):
        logmsg(f"{Colors.YELLOW}JWT expired — re-login via email/password...{Colors.RESET}")
        if email and password:
            token = await _http_login(args)
            if not token:
                logmsg(f"{Colors.RED}Re-login failed. Exiting.{Colors.RESET}")
                return
        else:
            logmsg(f"{Colors.RED}No email/password to re-login. Exiting.{Colors.RESET}")
            return

    # ===== 2) الاتصال بحساب DEMO =====
    logmsg(f"Connecting to Binolla ({'demo' if args['is_demo'] else 'real'} account)...")
    client = await connect_binolla(token, is_demo=args["is_demo"],
                                   max_attempts=3, proxies=args["proxies"] or None)
    if client is None:
        print(f"\n{Colors.RED}Connection failed after multiple attempts.{Colors.RESET}")
        return

    # حفظ الاعتمادات
    save_credentials(
        token=token,
        email=email,
        password=password,
        is_demo=args["is_demo"],
        proxy=args["proxies"],
    )
    print(f"{Colors.GREEN}Credentials saved to {CREDENTIALS_FILE.name}{Colors.RESET}\n")

    # ===== 3) جلب أولي لكل الأصول + نسبة الدفع + اشتراك في sentiment عام =====
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Initial fetch: all assets + payout% + live prices{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    initial = await fetch_all_assets_info(client, wait_seconds=8.0)
    if "error" not in initial:
        assets = initial.get("assets", [])
        print(f"{Colors.GREEN}Got {len(assets)} assets initially.{Colors.RESET}")

    # ===== 4) شغّل المهام الخلفية الثلاث =====
    stop_event = asyncio.Event()
    keepalive_task = asyncio.create_task(keepalive_loop(client, stop_event))
    jwt_refresh_task = asyncio.create_task(jwt_refresh_loop(client, args, stop_event))
    watchdog_task = asyncio.create_task(watchdog_reconnect_loop(client, args, stop_event))
    logmsg(f"{Colors.CYAN}Background tasks: keepalive(3s), JWT refresh, watchdog.{Colors.RESET}")

    # ===== 5) شغّل LivePriceStream (event-driven) =====
    live_stream = LivePriceStream(client.api)
    live_stream.start()
    logmsg(f"{Colors.CYAN}Live price stream started (event-driven — prints on every quote update).{Colors.RESET}")

    # ===== 6) (اختياري) جلب الشموع إذا طُلب عبر CLI =====
    if args.get("asset") and args.get("days"):
        try:
            asset = normalize_asset(args["asset"])
            days = int(args["days"])
            timeframe = int(args["timeframe"])
            print(f"\n{Colors.CYAN}Fetching candles for {asset} ({days}d, M{timeframe})...{Colors.RESET}")
            candles = await fetch_candles_for_asset(
                client, asset, days, timeframe, idx=1, total=1)
            if candles:
                filepath = save_candles_to_json(candles, asset, timeframe, days)
                print(f"{Colors.GREEN}Saved {len(candles)} candles to: {filepath.absolute()}{Colors.RESET}")
        except Exception as e:
            logmsg(f"{Colors.YELLOW}Candle fetch error: {e}{Colors.RESET}")

    # ===== 7) قائمة الأوامر التفاعلية =====
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.BOLD}  Ready. Type a command (or 'help').{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}")
    print_help()

    try:
        while True:
            try:
                cmd_line = await ainput(
                    f"{Colors.YELLOW}binolla> {Colors.RESET}"
                )
            except (EOFError, KeyboardInterrupt):
                break
            if not cmd_line.strip():
                continue
            should_continue = await process_command(
                cmd_line, client, args, live_stream)
            if not should_continue:
                break
    except (KeyboardInterrupt, asyncio.CancelledError):
        pass
    finally:
        stop_event.set()
        live_stream.stop()
        for t in (keepalive_task, jwt_refresh_task, watchdog_task):
            try:
                await asyncio.wait_for(t, timeout=2.0)
            except Exception:
                pass
        try:
            await client.close()
        except Exception:
            pass
        # احفظ لقطة نهائية
        try:
            if client.api and (client.api.assets_sentiment or client.api.assets_quotes):
                final = await fetch_all_assets_info(client, wait_seconds=0.5)
                if "error" not in final:
                    out = save_assets_info_to_json(final)
                    print(f"\n{Colors.GREEN}Final snapshot saved to: {out.absolute()}{Colors.RESET}")
        except Exception:
            pass
        print(f"{Colors.CYAN}Shutdown complete.{Colors.RESET}")


def _count_items(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, (list, tuple)):
        return str(len(x))
    if isinstance(x, dict):
        # قد يحتوي على list داخلية
        for k in ("assets", "data", "list", "items"):
            if k in x and isinstance(x[k], (list, tuple)):
                return f"{len(x[k])} (in .{k})"
        return str(len(x))
    return "?"


def _format_balances(x: Any) -> str:
    if x is None:
        return "n/a"
    if isinstance(x, dict):
        # Binolla قد يرسل: {"demoBalance": ..., "liveBalance": ...}
        parts = []
        for k in ("liveBalance", "demoBalance", "realBalance", "balance"):
            if k in x:
                parts.append(f"{k}={x[k]}")
        if parts:
            return ", ".join(parts)
    return _summary(x)


def _summary(x: Any, max_len: int = 80) -> str:
    if x is None:
        return "n/a"
    try:
        s = json.dumps(x, ensure_ascii=False)
    except Exception:
        s = str(x)
    if len(s) > max_len:
        return s[:max_len] + "..."
    return s


def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Stopped.{Colors.RESET}")
    except Exception as e:
        log_exception("main", e)


if __name__ == "__main__":
    main()
