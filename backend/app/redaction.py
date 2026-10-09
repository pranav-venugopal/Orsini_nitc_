"""Conservative pattern-based output redaction for common secrets and PII."""
import re


_RULES = (
    (
        "secret",
        re.compile(
            r"(?i)\b(?P<key>api[_ -]?key|access[_ -]?token|authorization|secret|password|client[_ -]?secret)"
            r"(?P<sep>\s*[:=]\s*)(?P<value>[A-Za-z0-9_./+=-]{8,})"
        ),
        lambda match: f"{match.group('key')}{match.group('sep')}[REDACTED_SECRET]",
    ),
    (
        "secret",
        re.compile(r"\b(?:sk-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[A-Z0-9]{16})\b"),
        "[REDACTED_SECRET]",
    ),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), "[REDACTED_SSN]"),
    (
        "phone",
        re.compile(r"(?<!\w)\+?(?:1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\w)"),
        "[REDACTED_PHONE]",
    ),
)


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    sanitized = text
    findings: list[str] = []
    for category, pattern, replacement in _RULES:
        if pattern.search(sanitized):
            sanitized = pattern.sub(replacement, sanitized)
            findings.append(category)
    return sanitized, findings