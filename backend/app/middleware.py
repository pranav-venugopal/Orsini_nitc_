"""Request size limits plus Redis-backed rate limiting and idempotency."""
import hashlib
import logging
import threading
import time
from collections import defaultdict, deque

from starlette.responses import JSONResponse

from .config import settings

logger = logging.getLogger(__name__)


class _BodyTooLarge(Exception):
    pass


class _MemoryLimiter:
    """Test-only fallback when REDIS_URL is intentionally unset."""

    def __init__(self):
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int) -> bool:
        now = time.monotonic()
        with self._lock:
            bucket = self._requests[key]
            while bucket and bucket[0] <= now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


class _RedisLimiter:
    _SCRIPT = """
    local count = redis.call('INCR', KEYS[1])
    if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end
    return count
    """

    def __init__(self, url: str):
        import redis

        self.client = redis.Redis.from_url(url, decode_responses=True)

    def allow(self, key: str, limit: int, window: int) -> bool:
        count = int(self.client.eval(self._SCRIPT, 1, key, window))
        return count <= limit

    def claim(self, key: str, ttl: int) -> bool:
        return bool(self.client.set(key, "1", nx=True, ex=ttl))


class RequestLimitsMiddleware:
    def __init__(self, app):
        self.app = app
        self._redis = _RedisLimiter(settings.redis_url) if settings.redis_url else None
        self._memory = _MemoryLimiter() if self._redis is None else None
        if self._memory is not None:
            logger.warning("REDIS_URL is unset; using process-local test/development rate limits without deduplication.")

    def _allow(self, key: str, limit: int, window: int) -> bool:
        try:
            if self._redis is not None:
                return self._redis.allow(key, limit, window)
            return self._memory.allow(key, limit, window)
        except Exception as exc:  # noqa: BLE001
            logger.error("Redis rate limiter unavailable: %s", type(exc).__name__)
            return False

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
        key = f"rate:{'chat' if is_chat else 'auth'}:{client}{'' if is_chat else ':' + scope['path']}"
        if not self._allow(key, rate_limit, rate_window):
            detail = "Chat rate limit exceeded." if is_chat else "Too many authentication attempts. Try again shortly."
            await JSONResponse({"detail": detail}, status_code=429)(scope, receive, send)
            return

        if is_chat and self._redis is not None:
            idempotency_key = headers.get(b"idempotency-key")
            if idempotency_key:
                digest = hashlib.sha256(client.encode("utf-8") + b":" + idempotency_key).hexdigest()
                try:
                    if not self._redis.claim(f"dedupe:chat:{digest}", settings.idempotency_ttl_seconds):
                        await JSONResponse({"detail": "Duplicate chat request."}, status_code=409)(scope, receive, send)
                        return
                except Exception as exc:  # noqa: BLE001
                    logger.error("Redis request deduplication unavailable: %s", type(exc).__name__)
                    await JSONResponse({"detail": "Request deduplication is unavailable."}, status_code=503)(scope, receive, send)
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
