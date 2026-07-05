from __future__ import annotations

import html
import json
import logging
import secrets
import string
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from random import SystemRandom
from typing import Any
from urllib.parse import parse_qs, urlsplit

CODE_LENGTH = 6
SESSION_COOKIE = "uv_agent_auth_code_session"
LETTERS = string.ascii_uppercase
DIGITS = string.digits
ALPHABET = LETTERS + DIGITS
_RANDOM = SystemRandom()


@dataclass(frozen=True)
class AuthCodeConfig:
    token: str
    host: str = "0.0.0.0"
    port: int = 8765
    ttl_s: int = 120
    session_ttl_s: int = 43200

    @classmethod
    def from_mapping(cls, value: dict[str, Any] | None) -> "AuthCodeConfig":
        data = dict(value or {})
        token = str(data.get("token") or "").strip()
        if not token:
            raise ValueError("auth-code config requires a non-empty token")
        host = str(data.get("host") or "0.0.0.0").strip() or "0.0.0.0"
        port = _int_range(data.get("port", 8765), "port", minimum=0, maximum=65535)
        ttl_s = _int_range(data.get("ttl_s", 120), "ttl_s", minimum=1, maximum=86400)
        session_ttl_s = _int_range(data.get("session_ttl_s", 43200), "session_ttl_s", minimum=60, maximum=604800)
        return cls(token=token, host=host, port=port, ttl_s=ttl_s, session_ttl_s=session_ttl_s)


class ChallengeStore:
    def __init__(self, *, ttl_s: int) -> None:
        self.ttl_s = ttl_s
        self._lock = threading.RLock()
        self._code = ""
        self._expires_at = 0.0

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            now = time.time()
            if self._is_expired(now):
                self._rotate_locked(now)
            return self._snapshot_locked(now)

    def verify(self, code: str) -> dict[str, Any]:
        candidate = normalize_code(code)
        with self._lock:
            now = time.time()
            if not candidate:
                return self._failure_locked("empty_code", now)
            if self._is_expired(now):
                self._rotate_locked(now)
                return self._failure_locked("expired", now)
            if not secrets.compare_digest(candidate, self._code):
                return self._failure_locked("invalid", now)
            self._rotate_locked(now)
            return {
                "ok": True,
                "verified": True,
                "ttl_s": self.ttl_s,
                "expires_at": _iso_utc(self._expires_at),
            }

    def _failure_locked(self, reason: str, now: float) -> dict[str, Any]:
        if self._is_expired(now):
            self._rotate_locked(now)
        return {
            "ok": False,
            "verified": False,
            "reason": reason,
            "ttl_s": self.ttl_s,
            "expires_at": _iso_utc(self._expires_at),
        }

    def _snapshot_locked(self, now: float) -> dict[str, Any]:
        return {
            "code": self._code,
            "ttl_s": self.ttl_s,
            "expires_at": _iso_utc(self._expires_at),
            "remaining_s": max(0, int(round(self._expires_at - now))),
        }

    def _is_expired(self, now: float) -> bool:
        return not self._code or now >= self._expires_at

    def _rotate_locked(self, now: float) -> None:
        self._code = generate_code()
        self._expires_at = now + self.ttl_s


class AuthCodeService:
    def __init__(self, config: AuthCodeConfig, *, logger: logging.Logger | None = None) -> None:
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.challenge = ChallengeStore(ttl_s=config.ttl_s)
        self._sessions = SessionStore(ttl_s=config.session_ttl_s)
        self._lock = threading.RLock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._url = ""

    @property
    def url(self) -> str:
        return self._url

    @property
    def port(self) -> int:
        with self._lock:
            if self._httpd is None:
                return self.config.port
            return int(self._httpd.server_address[1])

    def start(self) -> None:
        with self._lock:
            if self._httpd is not None:
                return
            handler = self._handler_class()
            httpd = ThreadingHTTPServer((self.config.host, self.config.port), handler)
            httpd.daemon_threads = True
            self._httpd = httpd
            host, port = httpd.server_address[:2]
            self._url = f"http://{_display_host(str(host))}:{port}"
            self._thread = threading.Thread(target=httpd.serve_forever, name="uv-agent-auth-code-http", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            httpd = self._httpd
            thread = self._thread
            self._httpd = None
            self._thread = None
            self._url = ""
        if httpd is not None:
            httpd.shutdown()
            httpd.server_close()
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def verify(self, code: str) -> dict[str, Any]:
        return self.challenge.verify(code)

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        service = self

        class AuthCodeRequestHandler(BaseHTTPRequestHandler):
            server_version = "UvAgentAuthCode/1"

            def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
                try:
                    self._handle_get()
                except Exception as exc:
                    service.logger.warning("Auth code HTTP request failed error_type=%s", exc.__class__.__name__)
                    self.send_error(HTTPStatus.INTERNAL_SERVER_ERROR)

            def log_message(self, _format: str, *_args: Any) -> None:
                return

            def _handle_get(self) -> None:
                parsed = urlsplit(self.path)
                params = parse_qs(parsed.query, keep_blank_values=True)
                if parsed.path == "/healthz":
                    self._send_bytes(HTTPStatus.OK, b"ok\n", content_type="text/plain; charset=utf-8")
                    return
                token = _first(params.get("token"))
                if token:
                    self._handle_token_login(token)
                    return
                if not self._authenticated():
                    self._send_unauthorized()
                    return
                if parsed.path in {"", "/", "/index.html"}:
                    self._send_html()
                    return
                if parsed.path == "/api/challenge":
                    self._send_json(service.challenge.snapshot())
                    return
                if parsed.path == "/logout":
                    self._logout()
                    return
                self.send_error(HTTPStatus.NOT_FOUND)

            def _handle_token_login(self, token: str) -> None:
                if not service._valid_token(token):
                    self._send_unauthorized()
                    return
                session_id = service._sessions.create()
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.send_header(
                    "Set-Cookie",
                    f"{SESSION_COOKIE}={session_id}; HttpOnly; SameSite=Lax; Path=/; Max-Age={service.config.session_ttl_s}",
                )
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _authenticated(self) -> bool:
                auth = str(self.headers.get("Authorization") or "")
                scheme, separator, token = auth.partition(" ")
                if separator and scheme.lower() == "bearer" and service._valid_token(token):
                    return True
                cookie = SimpleCookie()
                cookie.load(str(self.headers.get("Cookie") or ""))
                morsel = cookie.get(SESSION_COOKIE)
                return morsel is not None and service._sessions.valid(morsel.value)

            def _logout(self) -> None:
                cookie = SimpleCookie()
                cookie.load(str(self.headers.get("Cookie") or ""))
                morsel = cookie.get(SESSION_COOKIE)
                if morsel is not None:
                    service._sessions.delete(morsel.value)
                self.send_response(HTTPStatus.SEE_OTHER)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", f"{SESSION_COOKIE}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _send_html(self) -> None:
                snapshot = service.challenge.snapshot()
                body = _render_page(snapshot).encode("utf-8")
                self._send_bytes(HTTPStatus.OK, body, content_type="text/html; charset=utf-8")

            def _send_unauthorized(self) -> None:
                body = _render_unauthorized().encode("utf-8")
                self._send_bytes(HTTPStatus.UNAUTHORIZED, body, content_type="text/html; charset=utf-8")

            def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
                body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                self._send_bytes(status, body, content_type="application/json; charset=utf-8")

            def _send_bytes(self, status: HTTPStatus, body: bytes, *, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Cache-Control", "no-store")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        return AuthCodeRequestHandler

    def _valid_token(self, token: str) -> bool:
        return secrets.compare_digest(str(token or ""), self.config.token)


class SessionStore:
    def __init__(self, *, ttl_s: int) -> None:
        self.ttl_s = ttl_s
        self._lock = threading.RLock()
        self._sessions: dict[str, float] = {}

    def create(self) -> str:
        now = time.time()
        self._prune_locked(now)
        session_id = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions[session_id] = now + self.ttl_s
        return session_id

    def valid(self, session_id: str) -> bool:
        now = time.time()
        with self._lock:
            expires_at = self._sessions.get(session_id)
            if expires_at is None:
                return False
            if now >= expires_at:
                self._sessions.pop(session_id, None)
                return False
            return True

    def delete(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)

    def _prune_locked(self, now: float) -> None:
        with self._lock:
            expired = [session_id for session_id, expires_at in self._sessions.items() if now >= expires_at]
            for session_id in expired:
                self._sessions.pop(session_id, None)


def generate_code() -> str:
    chars = [secrets.choice(LETTERS), secrets.choice(DIGITS)]
    chars.extend(secrets.choice(ALPHABET) for _ in range(CODE_LENGTH - len(chars)))
    _RANDOM.shuffle(chars)
    return "".join(chars)


def normalize_code(code: str) -> str:
    return str(code or "").strip().upper()


def _render_page(snapshot: dict[str, Any]) -> str:
    code = html.escape(str(snapshot["code"]))
    expires_at = html.escape(str(snapshot["expires_at"]))
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auth Code</title>
  <style>
    :root {{
      color-scheme: light dark;
      font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #f7f9fb;
      color: #171717;
    }}
    body {{
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
    }}
    main {{
      width: min(92vw, 420px);
      padding: 32px;
      border: 1px solid #d8dee8;
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 18px 44px rgba(27, 31, 35, 0.12);
    }}
    h1 {{
      margin: 0 0 18px;
      font-size: 16px;
      font-weight: 650;
    }}
    #code {{
      display: block;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
      font-size: clamp(48px, 15vw, 82px);
      font-weight: 800;
      line-height: 1;
      letter-spacing: 0;
      margin: 8px 0 20px;
      overflow-wrap: anywhere;
      color: #166534;
    }}
    .meta {{
      display: flex;
      justify-content: space-between;
      gap: 16px;
      color: #596579;
      font-size: 14px;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        background: #111315;
        color: #f4f1ea;
      }}
      main {{
        background: #191c1f;
        border-color: #343941;
        box-shadow: none;
      }}
      #code {{
        color: #7ddf9c;
      }}
      .meta {{
        color: #bbb5aa;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <h1>Current challenge</h1>
    <output id="code">{code}</output>
    <div class="meta">
      <span id="remaining"></span>
      <time id="expires" datetime="{expires_at}">{expires_at}</time>
    </div>
  </main>
  <script>
    const codeEl = document.getElementById("code");
    const remainingEl = document.getElementById("remaining");
    const expiresEl = document.getElementById("expires");
    let expiresAt = Date.parse(expiresEl.dateTime);

    function tick() {{
      const seconds = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));
      remainingEl.textContent = seconds + "s";
      if (seconds <= 1) {{
        refresh();
      }}
    }}

    async function refresh() {{
      const response = await fetch("/api/challenge", {{cache: "no-store"}});
      if (!response.ok) {{
        location.reload();
        return;
      }}
      const data = await response.json();
      codeEl.textContent = data.code;
      expiresEl.textContent = data.expires_at;
      expiresEl.dateTime = data.expires_at;
      expiresAt = Date.parse(data.expires_at);
      tick();
    }}

    setInterval(tick, 250);
    setInterval(refresh, 5000);
    tick();
  </script>
</body>
</html>
"""


def _render_unauthorized() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Unauthorized</title>
</head>
<body>
  <main>Unauthorized</main>
</body>
</html>
"""


def _iso_utc(epoch_seconds: float) -> str:
    return datetime.fromtimestamp(epoch_seconds, UTC).isoformat().replace("+00:00", "Z")


def _display_host(host: str) -> str:
    if host in {"", "0.0.0.0", "::"}:
        return "127.0.0.1"
    return host


def _first(values: list[str] | None) -> str:
    if not values:
        return ""
    return str(values[0] or "")


def _int_range(value: Any, label: str, *, minimum: int, maximum: int) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"auth-code config {label} must be an integer") from exc
    if result < minimum or result > maximum:
        raise ValueError(f"auth-code config {label} must be between {minimum} and {maximum}")
    return result
