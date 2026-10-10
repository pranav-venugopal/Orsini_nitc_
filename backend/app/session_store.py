"""Per-conversation session persistence (Redis or memory LRU)."""
from collections import OrderedDict
import logging
import os
import threading

from guardrails_engine import Session
from .config import settings

logger = logging.getLogger(__name__)


class SessionStore:
    def __init__(self, redis_url: str | None = None, max_size: int = 1000):
        self.redis_url = redis_url
        self.max_size = max_size
        self._lock = threading.Lock()
        self._memory: OrderedDict[str, Session] = OrderedDict()
        self._redis = None
        if redis_url:
            try:
                import redis
                self._redis = redis.Redis.from_url(redis_url, decode_responses=True)
            except Exception as e:
                logger.warning("Failed to connect to Redis for sessions: %s", e)
                self._redis = None

    def get(self, conversation_id: str) -> Session:
        if not conversation_id:
            return Session()
        if self._redis:
            try:
                data = self._redis.hgetall(f"session:{conversation_id}")
                if data:
                    return Session(
                        strikes=int(data.get("strikes", 0)),
                        tool_calls=int(data.get("tool_calls", 0)),
                    )
            except Exception as exc:
                logger.error("Redis session get failed: %s", exc)
        with self._lock:
            if conversation_id in self._memory:
                self._memory.move_to_end(conversation_id)
                return self._memory[conversation_id]
            s = Session()
            self._memory[conversation_id] = s
            if len(self._memory) > self.max_size:
                self._memory.popitem(last=False)
            return s

    def save(self, conversation_id: str, session: Session) -> None:
        if not conversation_id:
            return
        if self._redis:
            try:
                self._redis.hset(f"session:{conversation_id}", mapping={
                    "strikes": session.strikes,
                    "tool_calls": session.tool_calls,
                })
                self._redis.expire(f"session:{conversation_id}", 86400)
            except Exception as exc:
                logger.error("Redis session save failed: %s", exc)
        with self._lock:
            self._memory[conversation_id] = session
            self._memory.move_to_end(conversation_id)
            if len(self._memory) > self.max_size:
                self._memory.popitem(last=False)


session_store = SessionStore(redis_url=os.getenv("REDIS_URL") or settings.redis_url)
