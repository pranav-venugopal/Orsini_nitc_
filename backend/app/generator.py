"""Answer generator. Interface = generate(message) -> str."""
from typing import Any

from .transformers_runtime import TransformersRuntime
from .config import settings

class GroqGenerator:
    def __init__(self, model_id: str = "openai/gpt-oss-20b"):
        self.model_id = model_id
        from groq import Groq
        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY must be set in .env for Groq support.")
        self.client = Groq(api_key=settings.groq_api_key)

    def generate(self, message: str, model_id: str | None = None) -> str:
        selected_model = model_id or self.model_id
        # GPT-OSS otherwise consumes the completion budget on hidden reasoning.
        options: dict[str, Any] = {}
        if selected_model.startswith("openai/gpt-oss-"):
            options["reasoning_effort"] = "low"
        response = self.client.chat.completions.create(
            model=selected_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a helpful, accurate assistant. Answer clearly and honestly. If you are uncertain, say so.",
                },
                {"role": "user", "content": message},
            ],
            max_tokens=512,
            temperature=0.2,
            **options,
        )
        answer = response.choices[0].message.content
        if not answer or not answer.strip():
            raise RuntimeError("Groq returned an empty completion")
        return answer.strip()

    def diagnostics(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "runtime_available": True,
            "runtime_message": "Groq cloud",
            "cuda_available": False,
            "gpu_name": None,
            "gpu_memory_allocated_gib": None,
            "gpu_memory_reserved_gib": None,
            "loaded": True,
            "device_map": None,
            "dtype": None,
            "last_error": None,
        }



class MockGenerator:
    def generate(self, message: str, model_id: str | None = None) -> str:
        if "[demo-unsafe-output]" in message.lower():
            return "UNSAFE_DEMO_OUTPUT (stand-in text that the mock output check flags)."
        return (
            "[stand-in answer: real Qwen model not connected yet] "
            f"You asked: {message[:200]}"
        )


class QwenGenerator:
    def __init__(self, model_id: str):
        self._runtime = TransformersRuntime(model_id)

    def generate(self, message: str, model_id: str | None = None) -> str:
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
