# Team workflow

## Roles
| Person | Owns |
|---|---|
| **You** | Frontend, FastAPI API, output redaction, request limits, events store, dashboard (implemented in this repo, push first) |
| **Member A: Model + Guard** | Real Qwen + Llama Guard in `backend/app/generator.py` and `guard.py` |
| **Member B: Safety eval + Integration** | Policy, evaluation quality, safe-retry, remaining hardening, demo walkthrough |

## Git flow
1. Work from the project root (`secure-ai-assistant`), not its parent folder. The project now has its own local `main` repository.
2. Run `git status --short` and check that it only lists project files. Add `.gitignore`, `README.md`, `backend`, `docs`, and `frontend`, review `git status` again, then commit the baseline.
3. Add the shared remote and push `main`. Everyone clones that shared repository before starting their branch.
4. Use `feat/real-models` (A) and `feat/eval-and-policy` (B). Keep PRs small, get one review, and run the backend tests plus frontend build before merging.
5. Never commit `.env`, access tokens, or model weights. The ignore rules cover local environment files, caches, and common weight files. Members download models on the machine where they run them; share model IDs and setup steps, not the weights.

For this Windows checkout, run these from PowerShell at the project root:
```powershell
git status --short
git add .gitignore README.md backend docs frontend
git status --short
git commit -m "Add secure AI assistant app"
git remote add origin <shared-repository-url>
git push -u origin main
```
Only run `git remote add` once. If the remote is already configured, use `git remote -v` to check it and push with `git push -u origin main`.

## Right now (today)
**You:** review the initial `git status`, commit and push the mock-mode app, then share the clone URL. Start both servers and click through the 4 demo states.
**Member A:** clone, run in mock mode, request access to `meta-llama/Llama-Guard-3-1B` on Hugging Face (gated), then download Qwen + Guard on the GPU machine and test each model independently. Do not add weights to the repository.
**Member B:** clone, run in mock mode, review the existing evaluation suite, add borderline and indirect-injection cases, and write the policy doc; keep API and schema contracts unchanged unless agreed with you and A.

## Member A: real models (replace the two stubs)
Interfaces must not change:
- `generator.generate(message: str) -> str`
- `guard.classify(text: str, role: "user" | "assistant") -> Check(label, categories)`

Steps:
1. `LlamaGuard.__init__`: load tokenizer + model once at startup (`guard_model_id`, `hf_token` from settings).
2. `classify`: apply Llama Guard chat template (role user for input, assistant for output), generate, parse `safe` or `unsafe\nS1,S2`. Anything unparsable -> `Check(label="error")`.
3. `QwenGenerator`: load once, use the chat template, set `max_new_tokens`, a system prompt, and a timeout.
4. Move blocking inference off the event loop if latency is high (`def` endpoints already run in a threadpool).
5. Set `MODEL_MODE=real`, run `pytest` (mock-specific tests will need `MODEL_MODE=mock`), then test the 4 demo states with real prompts.
6. Add real deps to `requirements.txt` (`torch`, `transformers`, `accelerate`).

## Member B: policy, evaluation, hardening
1. Define the Llama Guard category policy (which S-categories block) and the refusal wording; put it in `docs/POLICY.md`.
2. Extend `backend/eval/test_set.json` with borderline, indirect-injection, unauthorized-retrieval, and invalid-tool cases as those components are added. The current set has 30 attack and 8 benign cases.
3. Run `python -m eval.run_eval` from `backend/` against the local server after each guard/policy change. The harness calculates baseline/guarded ASR and false-refusal rates and saves the latest summary to SQLite for `GET /security/metrics` and the dashboard.
4. Define and document the exact Llama Guard category policy and refusal wording in `docs/POLICY.md`.
5. Implement the optional safe-retry in `pipeline.py` (marked TODO), only after defining bounded retry count and re-running the evaluation suite.
6. Tighten `CORS_ORIGINS` to the demo host before deployment and own the final demo walkthrough.

## Not implemented yet (do not claim in the demo)
- Caller authentication and per-user quotas. The current request limiter is per-IP, in-process, and intended for a single-instance demo.
- Tool proposal registry, per-user/tool/resource authorization, argument validation, approval flow, and sandboxed execution. The generator currently returns text only; no tool executes.
- Retrieval authorization or untrusted-context handling; this repository does not yet include a RAG victim app.
- Comprehensive PII detection. Current output redaction covers common regex patterns only; it is not a substitute for Presidio or a tuned detector.
- Streaming, detector timeouts, availability metrics, precision/recall, and citation/hallucination checks.

## You: after the push
- Polish: empty states, mobile check at 375px, keyboard pass, screenshots for the demo.
- Agree any contract change in `frontend/src/types/api.ts` and `backend/app/schemas.py` together.

## Definition of done (from the brief)
Prompt -> backend response shown; loading/blocked/error/completed visually distinct; UI status matches API; dashboard values real or clearly labeled; works at desktop + mobile; no keys in frontend; README accurate.
