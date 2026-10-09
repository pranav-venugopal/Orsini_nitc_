
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

from guardrails.validator_base import (
    Validator,
    PassResult,
    FailResult,
    register_validator,
)

MODEL_ID = "meta-llama/Llama-Guard-3-1B"


@register_validator(
    name="orsini/llama_guard_safety",
    data_type="string",
)
class LlamaGuardSafety(Validator):
    """Validate user messages with a local Llama Guard classifier."""

    def __init__(self, on_fail="exception"):
        super().__init__(on_fail=on_fail)

        self.tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
        self.model = AutoModelForCausalLM.from_pretrained(
            MODEL_ID,
            torch_dtype="auto",
            device_map="auto",
        )
        self.model.eval()

    def _validate(self, value, metadata):
        if not isinstance(value, str) or not value.strip():
            return FailResult(
                error_message="Empty or invalid input."
            )

        if len(value) > 10_000:
            return FailResult(
                error_message="Input exceeds the length limit."
            )

        messages = [{"role": "user", "content": value}]

        inputs = self.tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to(self.model.device)

        with torch.no_grad():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=100,
                do_sample=False,
            )

        generated = outputs[
            0, inputs["input_ids"].shape[-1]:
        ]

        result = self.tokenizer.decode(
            generated,
            skip_special_tokens=True,
            clean_up_tokenization_spaces=False,
        ).strip()

        classification = result.splitlines()[0].strip().lower()

        if classification == "safe":
            return PassResult()

        if classification == "unsafe":
            return FailResult(
                error_message="Llama Guard classified this input as unsafe."
            )

        # Unexpected output must not silently pass.
        return FailResult(
            error_message="Llama Guard returned an unknown classification."
        )
