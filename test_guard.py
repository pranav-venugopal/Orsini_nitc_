
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM

MODEL_ID = "meta-llama/Llama-Guard-3-1B"

print("Loading tokenizer...")
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)

print("Loading Llama Guard 3 1B...")
model = AutoModelForCausalLM.from_pretrained(
    MODEL_ID,
    torch_dtype="auto",
    device_map="auto",
)
model.eval()

def check_safety(user_message):
    messages = [
        {"role": "user", "content": user_message}
    ]

    inputs = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=True,
        return_tensors="pt",
        return_dict=True,
    ).to(model.device)

    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_new_tokens=100,
            do_sample=False,
        )

    new_tokens = outputs[0][inputs["input_ids"].shape[-1]:]
    result = tokenizer.decode(
        new_tokens,
        skip_special_tokens=True,
    ).strip()

    print("\nClassification:", result)

    if result.lower().startswith("safe"):
        return True
    if result.lower().startswith("unsafe"):
        return False

    # Fail closed if the classification is malformed.
    return None


if __name__ == "__main__":
    prompt = input("Enter a message to classify: ")
    result = check_safety(prompt)

    if result is True:
        print("Decision: ALLOW")
    elif result is False:
        print("Decision: BLOCK or REVIEW")
    else:
        print("Decision: UNKNOWN — block or escalate")
