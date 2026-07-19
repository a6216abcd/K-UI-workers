import json
import random
import ssl
import threading
import time
import uuid
import urllib.parse

try:
    import websocket
except ImportError:
    websocket = None


class RealtimeChannel:
    def __init__(self, base_url, ip, token, role, on_message=None):
        self.base_url = (base_url or "").rstrip("/")
        self.ip = ip
        self.token = token
        self.role = role
        self.on_message = on_message
        self.boot_id = str(uuid.uuid4())
        self.seq = 0
        self.connected = False
        self.last_connected = 0
        self.last_disconnected = 0
        self.outage_started = 0
        self.ever_connected = False
        self.last_message = 0
        self.started_at = 0
        self._socket = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    @property
    def enabled(self):
        parsed = urllib.parse.urlsplit(self.base_url)
        return bool(websocket and parsed.scheme == "https" and parsed.hostname and not parsed.username and not parsed.password and self.ip and self.token)

    def start(self):
        if not self.enabled or (self._thread and self._thread.is_alive()):
            return
        self.started_at = time.time()
        self._thread = threading.Thread(target=self._run, name=f"kui-realtime-{self.role}", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        try:
            if self._socket: self._socket.close()
        except Exception:
            pass

    def send(self, data, message_type="status"):
        with self._lock:
            if not self.connected or not self._socket:
                return False
            self.seq += 1
            envelope = {
                "v": 1,
                "role": self.role,
                "ip": self.ip,
                "boot_id": self.boot_id,
                "seq": self.seq,
                "ts": int(time.time() * 1000),
                "type": message_type,
                "data": data,
            }
            try:
                self._socket.send(json.dumps(envelope, separators=(",", ":")))
                return True
            except Exception:
                self.connected = False
                if not self.outage_started:
                    self.outage_started = time.time()
                self.last_disconnected = self.outage_started
                if self.on_message:
                    try: self.on_message({"type": "transport.disconnected"})
                    except Exception: pass
                return False

    def _websocket_url(self):
        if not self.enabled:
            raise ValueError("realtime URL must use HTTPS")
        scheme = "wss"
        base = self.base_url.split("://", 1)[-1]
        query = urllib.parse.urlencode({"ip": self.ip, "role": self.role})
        return f"{scheme}://{base}/agent/ws?{query}"

    def _run(self):
        delay = 1
        while not self._stop.is_set():
            try:
                self._socket = websocket.create_connection(
                    self._websocket_url(),
                    header=[f"Authorization: {self.token}"],
                    timeout=30,
                    sslopt={"cert_reqs": ssl.CERT_REQUIRED},
                    enable_multithread=True,
                )
                self._socket.settimeout(45)
                self.connected = True
                self.last_connected = time.time()
                self.outage_started = 0
                self.ever_connected = True
                if self.on_message:
                    try: self.on_message({"type": "transport.connected"})
                    except Exception: pass
                delay = 1
                self.send({"capabilities": ["http-fallback", "config-refresh", "config-result"]}, "hello")
                while not self._stop.is_set():
                    try:
                        raw = self._socket.recv()
                        if raw is None:
                            break
                        self.last_message = time.time()
                        if isinstance(raw, str) and raw == "pong":
                            continue
                        if self.on_message and isinstance(raw, str):
                            try: self.on_message(json.loads(raw))
                            except Exception: pass
                    except websocket.WebSocketTimeoutException:
                        try: self._socket.ping()
                        except Exception: break
            except Exception:
                pass
            finally:
                self.connected = False
                if not self.outage_started:
                    self.outage_started = time.time()
                self.last_disconnected = self.outage_started
                if self.on_message:
                    try: self.on_message({"type": "transport.disconnected"})
                    except Exception: pass
                try:
                    if self._socket: self._socket.close()
                except Exception:
                    pass
                self._socket = None
            self._stop.wait(delay + random.random())
            delay = min(delay * 2, 30)
