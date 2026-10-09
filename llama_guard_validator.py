
from guardrails.validator_base import (
    Validator,
    PassResult,
    FailResult,
    register_validator,
)
from guardrails_engine import LlamaGuardClassifier, Stage

MODEL_ID = "meta-llama/Llama-Guard-3-1B"


@register_validator(
    name="orsini/llama_guard_safety",
    data_type="string",
)
class LlamaGuardSafety(Validator):
    """Compatibility adapter for Guardrails AI using the native classifier."""

    def __init__(self, on_fail="exception"):
        super().__init__(on_fail=on_fail)

        self.classifier = LlamaGuardClassifier(model_id=MODEL_ID)

    def _validate(self, value, metadata):
        if not isinstance(value, str) or not value.strip():
            return FailResult(
                error_message="Empty or invalid input."
            )

        if len(value) > 10_000:
            return FailResult(
                error_message="Input exceeds the length limit."
            )

        try:
            findings = self.classifier.check(value, Stage.INPUT, [])
        except Exception as exc:  # noqa: BLE001
            return FailResult(error_message=f"Llama Guard unavailable: {type(exc).__name__}")

        if not findings:
            return PassResult()
        return FailResult(error_message=f"Llama Guard: {findings[0].reason}")
