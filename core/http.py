"""Shared HTTP sessions with bug-bounty identification and traffic controls."""

import threading
import time
from urllib.parse import urlparse

import requests

import config


class CrossHostRequestError(requests.RequestException):
    """Raised when a safe-profile scan attempts to leave its starting host."""


class _PerHostRateLimiter:
    def __init__(self):
        self._lock = threading.RLock()
        self._next_request = {}

    def wait(self, host):
        rate = max(float(config.REQUESTS_PER_SECOND), 0.1)
        interval = 1.0 / rate
        with self._lock:
            now = time.monotonic()
            request_at = max(now, self._next_request.get(host, now))
            self._next_request[host] = request_at + interval
        delay = request_at - now
        if delay > 0:
            time.sleep(delay)


_RATE_LIMITER = _PerHostRateLimiter()


def researcher_user_agent(default=None):
    handle = str(config.HACKERONE_HANDLE or "").strip()
    profile = str(config.BUG_BOUNTY_PROGRAM or "").strip().lower()
    if profile == "ring" and handle:
        return f"RingResearcher_{handle}"
    if config.RESEARCHER_USER_AGENT:
        return str(config.RESEARCHER_USER_AGENT).strip()
    return default or f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Security-Scanner"


class RateLimitedSession(requests.Session):
    """Requests session enforcing shared per-host limits and optional host pinning."""

    def __init__(self, default_user_agent=None):
        super().__init__()
        self.default_user_agent = default_user_agent
        self._origin_host = None
        self._origin_lock = threading.RLock()

    def request(self, method, url, **kwargs):
        parsed = urlparse(str(url))
        host = (parsed.hostname or "").lower()
        if config.BUG_BOUNTY_MODE and host:
            _RATE_LIMITER.wait(host)
        if config.BUG_BOUNTY_MODE and host:
            with self._origin_lock:
                if self._origin_host is None:
                    self._origin_host = host
                elif host != self._origin_host:
                    raise CrossHostRequestError(
                        f"Safe profile blocked cross-host request from "
                        f"{self._origin_host} to {host}"
                    )
            kwargs["allow_redirects"] = False

        headers = dict(kwargs.pop("headers", {}) or {})
        if config.BUG_BOUNTY_MODE or config.RESEARCHER_USER_AGENT:
            headers["User-Agent"] = researcher_user_agent(self.default_user_agent)
        else:
            headers.setdefault(
                "User-Agent",
                researcher_user_agent(self.default_user_agent),
            )
        if config.RESEARCHER_HEADER_NAME and config.RESEARCHER_HEADER_VALUE:
            headers[str(config.RESEARCHER_HEADER_NAME)] = str(
                config.RESEARCHER_HEADER_VALUE
            )
        kwargs["headers"] = headers
        return super().request(method, url, **kwargs)


def create_session(default_user_agent=None):
    return RateLimitedSession(default_user_agent)
