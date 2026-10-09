
import sys
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

from guardrails_engine import GuardrailsEngine


MODEL_ID = "Qwen/Qwen2.5-3B-Instruct"
REFUSAL = "Sorry, I can't help with that request."


class MainLLM:
    def __init__(self, model_id=MODEL_ID):
        self.model_id = model_id
        self.tokenizer = None
        self.model = None

    def load(self):
        if self.model is not None:
            return

        print(f"\nLoading main LLM: {self.model_id}")
        print("This may take a few minutes on first run...")

        self.tokenizer = AutoTokenizer.from_pretrained(
            self.model_id
        )

        self.model = AutoModelForCausalLM.from_pretrained(
            self.model_id,
            torch_dtype="auto",
            device_map="auto",
            low_cpu_mem_usage=True,
        ).eval()

        print("Main LLM loaded successfully.\n")

    def generate(self, prompt: str) -> str:
        self.load()

        messages = [
            {
                "role": "system",
                "content": (
                    "You are a helpful, accurate assistant. "
                    "Answer clearly and honestly. "
                    "If you are uncertain, say so."
                ),
            },
            {"role": "user", "content": prompt},
        ]

        inputs = self.tokenizer.apply_chat_template(
            messages,
            tokenize=True,
            add_generation_prompt=True,
            return_tensors="pt",
            return_dict=True,
        ).to(self.model.device)

        with torch.inference_mode():
            outputs = self.model.generate(
                **inputs,
                max_new_tokens=256,
                do_sample=False,
                pad_token_id=self.tokenizer.eos_token_id,
            )

        # Decode only the newly generated answer.
        input_length = inputs["input_ids"].shape[1]
        new_tokens = outputs[0][input_length:]

        answer = self.tokenizer.decode(
            new_tokens,
            skip_special_tokens=True,
        ).strip()

        return answer or "The model returned an empty response."


def main():
    # Uses your deterministic guards, PII guard, and injection guard.
    # Llama Guard remains disabled for this initial integration.
    engine = GuardrailsEngine()
    llm = MainLLM()

    print("=" * 55)
    print("       LLM GUARDRAIL GATEWAY")
    print("=" * 55)
    print(f"Main model: {MODEL_ID}")
    print("Type 'exit' to quit.")

    while True:
        try:
            prompt = input("\nYou: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting.")
            break

        if prompt.lower() in {"exit", "quit"}:
            break

        if not prompt:
            print("Please enter a message.")
            continue

        try:
            response, input_result, output_result = engine.protect(
                user_text=prompt,
                llm=llm.generate,
                refusal=REFUSAL,
            )

            print(
                f"\nInput guard:  {input_result.decision}"
                f" ({input_result.reason})"
            )

            if output_result is not None:
                print(
                    f"Output guard: {output_result.decision}"
                    f" ({output_result.reason})"
                )

            print(f"\nAssistant: {response}")

        except Exception as exc:
            # Do not expose internal errors or stack traces to the user.
            print("\nRequest failed safely.")
            print(f"Error type: {type(exc).__name__}")
            print("Check the terminal logs and model configuration.")


if __name__ == "__main__":
    main()
