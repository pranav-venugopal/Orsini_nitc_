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
        self._lock = threading.Lock()

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["method"] != "POST" or scope["path"] != "/chat":
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
        now = time.monotonic()
        rate_limited = False
        with self._lock:
            bucket = self._requests[client]
            cutoff = now - settings.chat_rate_window_seconds
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= settings.chat_rate_limit:
                rate_limited = True
            else:
                bucket.append(now)
            if len(self._requests) > 4096:
                self._requests = defaultdict(
                    deque,
                    {key: values for key, values in self._requests.items() if values and values[-1] > cutoff},
                )
        if rate_limited:
            await JSONResponse({"detail": "Chat rate limit exceeded."}, status_code=429)(scope, receive, send)
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