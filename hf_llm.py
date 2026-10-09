
import logging
import os
import random
import time

from dotenv import load_dotenv
from huggingface_hub import InferenceClient, InferenceTimeoutError
from huggingface_hub.errors import HfHubHTTPError

load_dotenv()

MODEL_ID = os.getenv(
    "HF_MODEL_ID",
    "Qwen/Qwen2.5-3B-Instruct",
)
HF_TOKEN = os.getenv("HF_TOKEN")
MAX_RETRIES = int(os.getenv("HF_MAX_RETRIES", "4"))
TIMEOUT_SECONDS = float(os.getenv("HF_TIMEOUT_SECONDS", "60"))

logger = logging.getLogger("hf_llm")


class MainLLM:
    def __init__(self):
        if not HF_TOKEN or HF_TOKEN == "hf_your_actual_token_here":
            raise RuntimeError(
                "Set a valid HF_TOKEN in your .env file."
            )

        if not 0 <= MAX_RETRIES <= 10:
            raise ValueError("HF_MAX_RETRIES must be between 0 and 10.")

        self.client = InferenceClient(
            model=MODEL_ID,
            token=HF_TOKEN,
            provider="auto",
            timeout=TIMEOUT_SECONDS,
        )

    @staticmethod
    def _status_code(exc):
        response = getattr(exc, "response", None)
        return getattr(response, "status_code", None)

    @staticmethod
    def _retry_after(exc):
        response = getattr(exc, "response", None)
        headers = getattr(response, "headers", {}) or {}
        value = headers.get("Retry-After")

        try:
            return min(max(float(value), 0), 60) if value else None
        except (TypeError, ValueError):
            return None

    def generate(self, prompt: str) -> str:
        messages = [
            {
                "role": "system",
                "content": (
                    "You are a helpful, accurate assistant. "
                    "Answer clearly and honestly. "
                    "If uncertain, say so."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        for attempt in range(MAX_RETRIES + 1):
            try:
                result = self.client.chat_completion(
                    messages=messages,
                    max_tokens=256,
                    temperature=0.2,
                )

                answer = result.choices[0].message.content

                if not answer or not answer.strip():
                    raise RuntimeError(
                        "Hugging Face returned an empty response."
                    )

                return answer.strip()

            except (InferenceTimeoutError, TimeoutError, ConnectionError) as exc:
                status = None
                retry_after = None

            except HfHubHTTPError as exc:
                status = self._status_code(exc)

                if status not in (408, 429, 500, 502, 503, 504):
                    logger.error(
                        "Non-retryable Hugging Face error: HTTP %s",
                        status,
                    )
                    raise RuntimeError(
                        f"Hugging Face inference failed (HTTP {status}). "
                        "Check token permissions, model access, and provider availability."
                    ) from exc

                retry_after = self._retry_after(exc)

            if attempt >= MAX_RETRIES:
                logger.error("Hugging Face retries exhausted.")
                raise RuntimeError(
                    "Hugging Face inference failed after retries. "
                    "Check provider availability and inference quota."
                ) from exc

            delay = retry_after
            if delay is None:
                delay = min(2 ** attempt + random.uniform(0, 1), 30)

            logger.warning(
                "Transient inference failure. Retry %s/%s in %.1f seconds.",
                attempt + 1,
                MAX_RETRIES,
                delay,
            )
            time.sleep(delay)

        raise RuntimeError("Unexpected inference retry state.")
