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
    (
        "secret",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        "[REDACTED_SECRET]",
    ),
    ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[REDACTED_EMAIL]"),
    ("ssn", re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)"), "[REDACTED_SSN]"),
    ("credit_card", re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"), "[REDACTED_CREDIT_CARD]"),
    (
        "phone",
        re.compile(r"(?<!\w)\+?(?:1[ .-]?)?(?:\(\d{3}\)|\d{3})[ .-]?\d{3}[ .-]?\d{4}(?!\w)"),
        "[REDACTED_PHONE]",
    ),
)


def _is_luhn_valid(number: str) -> bool:
    digits = [int(digit) for digit in number if digit.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def redact_sensitive(text: str) -> tuple[str, list[str]]:
    sanitized = text
    findings: list[str] = []
    for category, pattern, replacement in _RULES:
        if category == "credit_card":
            valid_numbers = [
                match.group()
                for match in pattern.finditer(sanitized)
                if _is_luhn_valid(match.group())
            ]
            if valid_numbers:
                for number in valid_numbers:
                    sanitized = sanitized.replace(number, replacement)
                findings.append(category)
            continue
        if pattern.search(sanitized):
            sanitized = pattern.sub(replacement, sanitized)
            findings.append(category)
    return sanitized, findings