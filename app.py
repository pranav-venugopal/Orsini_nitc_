
from guardrails import Guard
from llama_guard_validator import LlamaGuardSafety

# Load the classifier once.
validator = LlamaGuardSafety(on_fail="exception")

guard = Guard().use(validator)

print("Orsini Guardrails is ready.")
print("Type 'exit' to quit.")

while True:
    message = input("\nEnter a message: ")

    if message.strip().lower() in {"exit", "quit"}:
        break

    try:
        guard.validate(message)
        print("Decision: ALLOW")

    except Exception as exc:
        print("Decision: BLOCK or REVIEW")
        print("Reason:", str(exc))
