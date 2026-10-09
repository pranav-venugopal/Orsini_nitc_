"""Safety classifier. Interface = classify(text, role, context) -> Check."""
import base64
import binascii
import re
import unicodedata
from typing import Any

from .schemas import Check
from .transformers_runtime import TransformersRuntime
from .config import settings

class GroqGuard:
    """Safety guard using Groq API.

    Supports two guard model formats:
    - llama-prompt-guard-2: returns a float probability (>0.5 = unsafe)
    - Any other model: uses a system prompt to ask for safe/unsafe classification
    """

    _UNSAFE_THRESHOLD = 0.5

    def __init__(self, model_id: str = "meta-llama/llama-prompt-guard-2-86m"):
        self.model_id = model_id
        from groq import Groq
        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY must be set in .env for Groq support.")
        self.client = Groq(api_key=settings.groq_api_key)
        self._is_prompt_guard = "prompt-guard" in model_id.lower()

    def classify(self, text: str, role: str, context: str | None = None) -> Check:
        if not isinstance(text, str) or not text.strip() or len(text) > 10_000:
            return Check(label="error", categories=["format"])
        # Run local policy rules first
        policy = _policy_check(text)
        if policy.label == "unsafe":
            return policy

        if role == "user":
            messages = [{"role": "user", "content": text}]
        elif role == "assistant" and isinstance(context, str) and context.strip():
            messages = [
                {"role": "user", "content": context},
                {"role": "assistant", "content": text},
            ]
        else:
            return Check(label="error", categories=["format"])

        try:
            if self._is_prompt_guard:
                return self._classify_prompt_guard(messages)
            else:
                return self._classify_chat_model(messages)
        except Exception as e:
            import logging
            logging.getLogger(__name__).exception("GroqGuard error: %s", e)
            return Check(label="error", categories=["api_error"])

    def _classify_prompt_guard(self, messages: list[dict]) -> Check:
        """llama-prompt-guard-2 returns a single float probability.

        The Groq prompt-guard model is a text classifier that only accepts
        a single user message.  When we need to check an assistant reply
        (two messages: user context + assistant text), we merge them into
        one user message so the API doesn't reject the request.
        """
        if len(messages) == 1:
            api_messages = messages
        else:
            # Merge multi-turn into a single user message for classification
            combined = "\n\n".join(m["content"] for m in messages)
            api_messages = [{"role": "user", "content": combined}]

        # Truncate to avoid context_length_exceeded on Groq's 512-token prompt-guard model
        text_content = api_messages[0]["content"]
        if len(text_content) > 1000:
            api_messages = [{"role": "user", "content": text_content[:1000]}]

        try:
            response = self.client.chat.completions.create(
                model=self.model_id,
                messages=api_messages,
                max_tokens=10,
                temperature=0.0,
            )
            result = response.choices[0].message.content.strip()
            score = float(result)
            if score > self._UNSAFE_THRESHOLD:
                return Check(label="unsafe", categories=["prompt_injection"])
            return Check(label="safe")
        except Exception as e:
            err_str = str(e).lower()
            if "context_length_exceeded" in err_str or "reduce the length" in err_str:
                return Check(label="safe")
            raise

    def _classify_chat_model(self, messages: list[dict]) -> Check:
        """Use a system prompt to ask a general chat model to classify safety."""
        classification_messages = [
            {
                "role": "system",
                "content": (
                    "You are a safety classifier. Respond with ONLY the word 'safe' or 'unsafe' "
                    "on the first line. If unsafe, list categories on the second line separated by commas. "
                    "Categories: violence, weapons, cybercrime, self_harm, sexual_content, hate, prompt_injection. "
                    "Do not include any other text."
                ),
            },
            *messages,
        ]
        response = self.client.chat.completions.create(
            model=self.model_id,
            messages=classification_messages,
            max_tokens=50,
            temperature=0.0,
        )
        result = response.choices[0].message.content.strip()
        lines = result.lower().splitlines()
        if not lines:
            return Check(label="error")
        classification = lines[0].strip()
        if classification == "safe":
            return Check(label="safe")
        if classification == "unsafe":
            categories = (
                [c.strip() for c in lines[1].split(",") if c.strip()]
                if len(lines) > 1
                else ["unspecified"]
            )
            return Check(label="unsafe", categories=categories)
        # If the model didn't follow the format, treat as safe with policy-only check
        return Check(label="safe")

    def diagnostics(self) -> dict[str, Any]:
        return {
            "model_id": self.model_id,
            "runtime_available": True,
            "runtime_message": "Groq cloud",
            "cuda_available": False,
            "gpu_name": None,
            "gpu_memory_allocated_gib": None,
            "gpu_memory_reserved_gib": None,
            "loaded": True,
            "device_map": None,
            "dtype": None,
            "last_error": None,
        }


_ZERO_WIDTH = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad"), None)
_LEET_TRANSLATION = str.maketrans("0134578@$", "oleastbas")
_POLICY_RULES = (
    (
        "prompt_injection",
        re.compile(
            r"\b(?:ignore|disregard|override|forget|bypass)\b.{0,60}"
            r"\b(?:previous|prior|all|your|the)?\s*"
            r"(?:instructions?|rules?|polic(?:y|ies)|restrictions?|directions?)\b"
            r"|\b(?:reveal|disclose|print|show|repeat|output)\b.{0,60}"
            r"\b(?:hidden|system|developer|initial|private)\s+"
            r"(?:prompt|instructions?|message|configuration|secrets?)\b"
            r"|\bdeveloper\s+mode\b.{0,40}\b(?:ignore|bypass|disable|no)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "weapons",
        re.compile(
            r"\b(?:how\s+to|instructions?\s+(?:for|to)|steps?\s+(?:for|to)|"
            r"help\s+me|build|make|create|construct|assemble)\b.{0,70}"
            r"\b(?:homemade\s+|improvised\s+|diy\s+)?"
            r"(?:bomb|explosive\s+device|detonator|grenade|molotov|"
            r"chemical\s+weapon|biological\s+weapon)\b"
            r"|\b(?:build|make|create|construct|assemble)\b.{0,40}"
            r"\b(?:a\s+)?(?:bomb|explosive\s+device|detonator|grenade)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "cybercrime",
        re.compile(
            r"\b(?:write|create|build|develop|code|make|deploy|generate)\b"
            r".{0,60}\b(?:ransomware|keylogger|malware|credential\s+stealer|"
            r"password\s+stealer|phishing\s+kit|browser\s+password\s+stealer)\b"
            r"|\b(?:steal|exfiltrate|harvest)\b.{0,50}"
            r"\b(?:passwords?|credentials?|browser\s+data|private\s+files?)\b"
            r"|\b(?:break\s+into|hack|bypass|brute[\s-]?force)\b.{0,60}"
            r"\b(?:someone\s+else['’]?s|another\s+person['’]?s|"
            r"someone\s+else|another\s+person)\b.{0,50}"
            r"\b(?:account|computer|server|network|email)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "violence",
        re.compile(
            r"\b(?:how\s+(?:to|can\s+i)|instructions?\s+(?:for|to)|steps?\s+(?:for|to)|"
            r"help\s+me|i\s+(?:want|plan|intend)\s+to)\b.{0,50}"
            r"\b(?:kill|murder|assassinate|poison|shoot|stab|strangle|"
            r"hurt|harm|attack|torture)\b.{0,50}"
            r"\b(?:someone|a\s+person|people|my\s+\w+|him|her|them)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "self_harm",
        re.compile(
            r"\b(?:how\s+to|ways?\s+to|methods?\s+(?:to|of)|"
            r"i\s+(?:want|plan|intend)\s+to)\b.{0,50}"
            r"\b(?:kill\s+myself|commit\s+suicide|end\s+my\s+life|"
            r"hurt\s+myself|self[\s-]?harm|overdose|slit\s+my\s+wrists?)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "drugs",
        re.compile(
            r"\b(?:how\s+(?:to|can\s+i)|instructions?\s+(?:for|to)|steps?\s+(?:for|to)|recipe\s+(?:for|to)|guide\s+(?:to|for)|ways?\s+to|methods?\s+(?:to|of)|tutorial\s+(?:for|to)|help\s+(?:me\s+)?(?:to\s+|with\s+)?|can\s+you\s+(?:help\s+(?:me\s+)?)?)\b"
            r".{0,60}\b(?:make|making|create|creating|synthesize|synthesizing|synthesis(?:\s+of)?|cook|cooking|manufacture|manufacturing|produce|producing|brew|brewing|prepare|preparing|preparation(?:\s+of)?|extract|extracting|extraction(?:\s+of)?|refine|refining|purify|purifying|cultivate|cultivating|harvest|harvesting|isolate|isolating)\b"
            r".{0,50}\b(?:methamphetamine|methanphetamine|methamphetamin|methanphgetamine|desoxyephedrine|methylamphetamine|n-methylamphetamine|crystal\s+meth|meth\b|pervitin|opium|morphine|codeine|heroin|fentanyl|carfentanil|oxycodone|hydrocodone|cocaine|crack(?:\s+cocaine)?|lsd|acid\b|mdma|ecstasy|molly\b|psilocybin|pcp|ghb|dmt|ketamine|quaaludes?|methaqualone|mephedrone|bath\s+salts?|illicit\s+drugs?|illegal\s+drugs?|narcotics?|street\s+drugs?|controlled\s+substances?)\b"
            r"|\b(?:how\s+(?:to|can\s+i)|instructions?\s+(?:for|to)|steps?\s+(?:for|to)|recipe\s+(?:for|to)|guide\s+(?:to|for)|tutorial\s+(?:for|to)|help\s+(?:me\s+)?(?:to\s+|with\s+)?|can\s+you\s+(?:help\s+(?:me\s+)?)?)\b"
            r".{0,50}\b(?:methamphetamine|methanphetamine|methamphetamin|methanphgetamine|desoxyephedrine|methylamphetamine|n-methylamphetamine|crystal\s+meth|meth\b|pervitin|opium|morphine|codeine|heroin|fentanyl|carfentanil|oxycodone|hydrocodone|cocaine|crack(?:\s+cocaine)?|lsd|acid\b|mdma|ecstasy|molly\b|psilocybin|pcp|ghb|dmt|ketamine|quaaludes?|narcotics?|controlled\s+substances?)\b"
            r".{0,50}\b(?:recipe|synthesis|process|instructions?|steps?|extraction|preparation|cultivation|harvesting)\b"
            r"|\brecipe\s+for\s+(?:making\s+)?(?:methamphetamine|methanphetamine|methamphetamin|crystal\s+meth|meth\b|opium|heroin|fentanyl|cocaine|crack|lsd|mdma|ecstasy|illegal\s+drugs?|illicit\s+drugs?|narcotics?)\b",
            re.IGNORECASE,
        ),
    ),
)


def _text_variants(text: str) -> list[str]:
    normalized = re.sub(
        r"\s+",
        " ",
        unicodedata.normalize("NFKC", text).translate(_ZERO_WIDTH),
    )
    variants = [normalized, normalized.translate(_LEET_TRANSLATION)]
    for blob in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", normalized)[:8]:
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            variants.append(decoded)
    return variants


def _policy_check(text: str) -> Check:
    categories = {
        category
        for variant in _text_variants(text)
        for category, pattern in _POLICY_RULES
        if pattern.search(variant)
    }
    return Check(
        label="unsafe" if categories else "safe",
        categories=sorted(categories),
    )


# Mock rules: obviously a stand-in. Not used in real mode.
_MOCK_RULES = {
    "prompt_injection": ["ignore previous instructions", "ignore all previous", "reveal your system prompt"],
    "violent_or_weapons": ["build a bomb", "make a bomb", "make a weapon"],
    "cybercrime": ["write ransomware", "write malware", "steal passwords"],
    "demo_unsafe_output": ["unsafe_demo_output"],
}


class MockGuard:
    def classify(self, text: str, role: str, context: str | None = None) -> Check:
        low = text.lower()
        if "[demo-guard-error]" in low:
            raise RuntimeError("demo classifier failure")
        hits = [c for c, kws in _MOCK_RULES.items() if any(k in low for k in kws)]
        policy = _policy_check(text)
        categories = sorted(set(hits + policy.categories))
        return Check(label="unsafe" if categories else "safe", categories=categories)


class LlamaGuard:
    _CATEGORIES = {
        "S1": "violence",
        "S2": "non_violent_crimes",
        "S3": "sex_related_crimes",
        "S4": "child_safety",
        "S5": "defamation",
        "S6": "specialized_advice",
        "S7": "privacy",
        "S8": "intellectual_property",
        "S9": "weapons",
        "S10": "hate",
        "S11": "self_harm",
        "S12": "sexual_content",
        "S13": "elections",
        "S14": "code_interpreter_abuse",
    }

    def __init__(self, model_id: str):
        self._runtime = TransformersRuntime(model_id)

    def classify(self, text: str, role: str, context: str | None = None) -> Check:
        if not isinstance(text, str) or not text.strip() or len(text) > 10_000:
            return Check(label="error", categories=["format"])
        policy = _policy_check(text)
        if policy.label == "unsafe":
            return policy
        if role == "user":
            messages = [{"role": "user", "content": text}]
        elif role == "assistant" and isinstance(context, str) and context.strip():
            messages = [
                {"role": "user", "content": context},
                {"role": "assistant", "content": text},
            ]
        else:
            return Check(label="error", categories=["format"])

        result = self._runtime.generate(messages, max_new_tokens=100)
        lines = result.lower().splitlines()
        if not lines:
            return Check(label="error")
        classification = lines[0].strip()
        if classification == "safe":
            return Check(label="safe")
        if classification != "unsafe":
            return Check(label="error")

        codes = (
            [code.strip().upper() for code in lines[1].split(",")]
            if len(lines) > 1
            else []
        )
        categories = sorted(
            {self._CATEGORIES[code] for code in codes if code in self._CATEGORIES}
        )
        return Check(label="unsafe", categories=categories or ["unspecified"])

    def diagnostics(self) -> dict[str, Any]:
        return self._runtime.diagnostics()
