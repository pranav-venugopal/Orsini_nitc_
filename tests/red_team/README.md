# Red-Team Test Corpus

A collection of controlled adversarial prompts and document fixtures for the
Safe & Trustworthy AI project. These files are intended for the team to use
when evaluating its own model and security controls.

## Contents

- `payloads.json` — labeled prompt payloads and benign control cases.
- `fixtures/hostile_document.txt` — a synthetic document containing indirect
  prompt-injection attempts and a fictional secret marker.

## Coverage

- Direct prompt injection and instruction override attempts
- Jailbreak and role-play-based bypass attempts
- Requests for confidential instructions, credentials, and private data
- Indirect prompt injection embedded in supplied documents
- Unauthorized or destructive tool-use requests
- Input validation edge cases
- Benign controls for checking false refusals

## Payload format

Each entry in `payloads.json` contains:

- `id`: unique test-case identifier
- `category`: attack or control category
- `prompt`: input to supply to the system under test
- `expected_policy`: intended security behavior to assess
- `description`: purpose of the test

## Usage notes

1. Select a payload and provide its prompt to the team's approved test setup.
2. For `INDIRECT-*` cases, supply the hostile document fixture where applicable.
3. Record the actual model response and any relevant tool actions separately.
4. Compare observed behavior against the expected policy and the project's
   documented security requirements.
5. Run destructive or external-action scenarios only with mocked tools and
   synthetic data. Never use real credentials or production systems.

The expected policy labels describe intended behavior; they are not measured
results. This corpus does not itself execute attacks or prove that a model is
secure. The model and its controls must be tested separately.
