
import os

import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

from guardrails_engine import GuardrailsEngine
from prompts import SYSTEM_PROMPT


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

        print("\nMain LLM loaded successfully.")
        print(f"Model ID: {self.model_id}")
        print(f"Model dtype: {self.model.dtype}")

        # Report actual model placement.
        device_map = getattr(self.model, "hf_device_map", None)

        if device_map:
            print("Model device map:")
            for module_name, device in device_map.items():
                print(f"  {module_name}: {device}")
        else:
            print(f"Model device: {self.model.device}")

        # Report GPU details when CUDA is available.
        if torch.cuda.is_available():
            print(f"CUDA available: {torch.cuda.is_available()}")
            print(f"GPU: {torch.cuda.get_device_name(0)}")
            print(
                "GPU memory allocated: "
                f"{torch.cuda.memory_allocated(0) / 1024**3:.2f} GiB"
            )
            print(
                "GPU memory reserved: "
                f"{torch.cuda.memory_reserved(0) / 1024**3:.2f} GiB"
            )
        else:
            print("CUDA is unavailable to PyTorch.")

        print()

    def generate(self, prompt: str) -> str:
        self.load()

        messages = [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
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

        # Show memory after generation for GPU diagnostics.
        if torch.cuda.is_available():
            print(
                "GPU memory allocated after generation: "
                f"{torch.cuda.memory_allocated(0) / 1024**3:.2f} GiB"
            )

        return answer or "The model returned an empty response."


def main():
    # Safety remains local and independent from the local generation model.
    engine = GuardrailsEngine(
        GuardrailsEngine.default_guards(
            use_llama_guard=True,
            llama_guard_model_id=os.getenv("LLAMA_GUARD_MODEL_ID", "meta-llama/Llama-Guard-3-1B"),
        )
    )
    
    llm = MainLLM()

    print("=" * 55)
    print("       LLM GUARDRAIL GATEWAY")
    print("=" * 55)
    print(f"Main model: {MODEL_ID}")
    print("Inference: local Transformers model")
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
            print("\nRequest failed safely.")
            print(f"Error type: {type(exc).__name__}")
            print("Check the terminal logs and model configuration.")


if __name__ == "__main__":
    main()
