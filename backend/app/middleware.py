"""In-process request size and per-client chat rate limits."""
import threading
import time
from collections import defaultdict, deque

from starlette.responses import JSONResponse

from .config import settings


class _BodyTooLarge(Exception):
    pass


class RequestLimitsMiddleware:
    def __init__(self, app):
        self.app = app
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._auth_requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] not in ("/chat", "/auth/login", "/auth/register"):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope["headers"]}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > settings.max_request_bytes:
                    await JSONResponse({"detail": "Request body too large."}, status_code=413)(scope, receive, send)
                    return
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length."}, status_code=400)(scope, receive, send)
                return

        client_info = scope.get("client")
        client = client_info[0] if client_info else "unknown"
        is_chat = scope["path"] == "/chat"
        rate_limit = settings.chat_rate_limit if is_chat else settings.auth_rate_limit
        rate_window = settings.chat_rate_window_seconds if is_chat else settings.auth_rate_window_seconds
        now = time.monotonic()
        rate_limited = False
        with self._lock:
            request_buckets = self._requests if is_chat else self._auth_requests
            key = client if is_chat else f"{client}:{scope['path']}"
            bucket = request_buckets[key]
            cutoff = now - rate_window
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= rate_limit:
                rate_limited = True
            else:
                bucket.append(now)
            if len(request_buckets) > 4096:
                request_buckets = defaultdict(
                    deque,
                    {key: values for key, values in request_buckets.items() if values and values[-1] > cutoff},
                )
                if is_chat:
                    self._requests = request_buckets
                else:
                    self._auth_requests = request_buckets
        if rate_limited:
            detail = "Chat rate limit exceeded." if is_chat else "Too many authentication attempts. Try again shortly."
            await JSONResponse({"detail": detail}, status_code=429)(scope, receive, send)
            return

        size = 0
        async def limited_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > settings.max_request_bytes:
                    raise _BodyTooLarge
            return message

        response_started = False

        async def track_response(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, track_response)
        except _BodyTooLarge:
            if not response_started:
                await JSONResponse({"detail": "Request body too large."}, status_code=413)(scope, receive, send)