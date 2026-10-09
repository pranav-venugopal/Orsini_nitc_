"""Groq API inference backend.

Same interface as MainLLM: call .generate(prompt) -> str.
Set GROQ_API_KEY and optionally GROQ_MODEL_ID in your environment or .env file.
"""

import logging
import os

from groq import Groq

logger = logging.getLogger("groq_llm")

GROQ_MODEL_ID = os.getenv("GROQ_MODEL_ID", "llama-3.1-8b-instant")


class GroqLLM:
    def __init__(self, model_id: str = GROQ_MODEL_ID):
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError(
                "Set GROQ_API_KEY in your environment or .env file. "
                "Get one free at https://console.groq.com/keys"
            )
        self.model_id = model_id
        self.client = Groq(api_key=api_key)
        # Expose .model attribute as None so api.py health check works uniformly.
        self.model = None
        logger.info("Groq client ready — model: %s", self.model_id)

    def generate(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model_id,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a helpful, accurate assistant. "
                        "Answer clearly and honestly. "
                        "If you are uncertain, say so."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=512,
            temperature=0.2,
        )

        answer = response.choices[0].message.content
        if not answer or not answer.strip():
            raise RuntimeError("Groq returned an empty response.")

        logger.info(
            "Groq response — model: %s, tokens: %s/%s",
            response.model,
            response.usage.prompt_tokens,
            response.usage.completion_tokens,
        )
        return answer.strip()
