"""Answer generator. Interface = generate(message) -> str.

OWNER: model/security person. Replace QwenGenerator.generate with real inference.
"""


class MockGenerator:
    def generate(self, message: str) -> str:
        if "[demo-unsafe-output]" in message.lower():
            return "UNSAFE_DEMO_OUTPUT (stand-in text that the mock output check flags)."
        return (
            "[stand-in answer: real Qwen model not connected yet] "
            f"You asked: {message[:200]}"
        )


class QwenGenerator:
    def __init__(self, model_id: str, hf_token: str | None):
        # TODO(model owner): load Qwen 3B Instruct (transformers) once at startup.
        raise NotImplementedError("Wire Qwen 3B Instruct here")

    def generate(self, message: str) -> str:
        raise NotImplementedError
