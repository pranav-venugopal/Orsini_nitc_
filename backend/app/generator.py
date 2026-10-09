"""Answer generator. Interface = generate(message) -> str."""
from typing import Any

from .transformers_runtime import TransformersRuntime


class MockGenerator:
    def generate(self, message: str) -> str:
        if "[demo-unsafe-output]" in message.lower():
            return "UNSAFE_DEMO_OUTPUT (stand-in text that the mock output check flags)."
        return (
            "[stand-in answer: real Qwen model not connected yet] "
            f"You asked: {message[:200]}"
        )


class QwenGenerator:
    def __init__(self, model_id: str):
        self._runtime = TransformersRuntime(model_id)

    def generate(self, message: str) -> str:
        return self._runtime.generate(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a helpful, accurate assistant. "
                        "Answer clearly and honestly. If you are uncertain, say so."
                    ),
                },
                {"role": "user", "content": message},
            ],
            max_new_tokens=256,
        )

    def diagnostics(self) -> dict[str, Any]:
        return self._runtime.diagnostics()
