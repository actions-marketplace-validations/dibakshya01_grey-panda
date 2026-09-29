"""
dlp.py — Data Loss Prevention: detect and redact PII and secrets.

Runs on any text *before* it reaches an LLM, a log, a vector store, or a
third-party API. This is the control that keeps regulated data and credentials
out of places they must never appear.

Addresses:
    * LLM02:2026 Sensitive Information Disclosure
    * DSGAI01    Sensitive Data Leakage
    * DSGAI14    Excessive Telemetry & Monitoring Leakage (never log raw matches)
    * AISVS C8   Memory, Embeddings & Vector Database Security (pre-embedding scrub)

Honesty (see WHAT_IT_CAN_AND_CANNOT_DO.md): regex DLP is language- and
format-specific. It catches structured identifiers and known secret shapes; it
does NOT understand meaning, so paraphrased or free-text disclosures can slip
through. Use it as a strong, cheap first pass — not a guarantee.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger("greypanda.dlp")

# Category -> list of (pattern_name, compiled_regex)
_Pattern = tuple[str, "re.Pattern[str]"]


def _c(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)


# --------------------------------------------------------------------------- #
# Built-in pattern catalogue. Universal categories ship on; regional and
# org-specific categories are opt-in and meant to be customised per adopter.
# --------------------------------------------------------------------------- #
_BUILTIN: dict[str, list[_Pattern]] = {
    "pii": [
        ("email", _c(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
        # Card-shaped numbers (13-19 digits, optional separators). Luhn-checked below.
        ("credit_card", _c(r"\b(?:\d[ -]?){13,19}\b")),
        ("us_ssn", _c(r"\b\d{3}-\d{2}-\d{4}\b")),
        ("phone", _c(r"\b(?:\+?\d{1,3}[ -]?)?(?:\(?\d{3}\)?[ -]?)\d{3}[ -]?\d{4}\b")),
        ("ipv4", _c(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
    ],
    "secrets": [
        ("aws_access_key", _c(r"\b(?:AKIA|ASIA|AGPA|AIDA)[0-9A-Z]{16}\b")),
        ("aws_secret_key", _c(r"(?i)aws.{0,20}(?:secret|private).{0,20}[=:]\s*['\"]?[0-9A-Za-z/+]{40}['\"]?")),
        ("gcp_api_key", _c(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
        ("github_token", _c(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b")),
        ("slack_token", _c(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
        ("openai_key", _c(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b")),
        ("anthropic_key", _c(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b")),
        ("jwt", _c(r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")),
        ("private_key_block", _c(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----")),
        ("generic_secret_assignment", _c(
            r"(?i)\b(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|password|passwd|client[_-]?secret)\b"
            r"\s*[=:]\s*['\"][^'\"]{8,}['\"]"
        )),
    ],
    # Regional identifiers — opt-in. Enable the ones relevant to your users.
    "regional_in": [  # India
        ("aadhaar", _c(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b")),
        ("pan", _c(r"\b[A-Z]{5}\d{4}[A-Z]\b")),
        ("phone_in", _c(r"\b(?:\+?91[ -]?)?[6-9]\d{9}\b")),
    ],
    "regional_eu": [  # EU
        ("iban", _c(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")),
    ],
    # org_pii is a template. Replace these with your customer/order/seller ID
    # formats before shipping. See docs/PROFILES.md.
    "org_pii": [
        # ("customer_id", _c(r"\bCUST-\d{8}\b")),
        # ("order_id",    _c(r"\bORD-[A-Z0-9]{10}\b")),
        # ("seller_id",   _c(r"\bSLR-\d{6}\b")),
    ],
}

_DEFAULT_CATEGORIES = ("pii", "secrets")


def _luhn_ok(digits: str) -> bool:
    d = [int(x) for x in digits if x.isdigit()]
    if len(d) < 13:
        return False
    checksum = 0
    for i, n in enumerate(reversed(d)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


@dataclass
class DLPMatch:
    """A single detection. ``masked_snippet`` never contains the full value."""

    category: str
    pattern_name: str
    masked_snippet: str


@dataclass
class DLPResult:
    clean: bool
    matches: list[DLPMatch] = field(default_factory=list)
    redacted_text: str = ""


def mask(value: str) -> str:
    """Mask a sensitive value: first 3 + ***** + last 3. Never log the raw value."""
    v = value.strip()
    if len(v) <= 6:
        return "*" * len(v)
    return f"{v[:3]}*****{v[-3:]}"


class DLPScanner:
    """Detect and redact PII and secrets from text.

    Args:
        categories: Which built-in categories to enable. Defaults to
            ``("pii", "secrets")``. Options also include ``"regional_in"``,
            ``"regional_eu"`` and ``"org_pii"``.
        custom_patterns: Extra patterns as ``{category: [(name, regex), ...]}``.
        on_violation: Optional callback invoked with the :class:`DLPResult` when a
            scan is not clean — wire this to your SIEM/alerting.
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        custom_patterns: dict[str, list[tuple[str, str]]] | None = None,
        on_violation: Callable[[DLPResult], None] | None = None,
    ) -> None:
        cats = list(categories) if categories is not None else list(_DEFAULT_CATEGORIES)
        self._patterns: list[tuple[str, str, "re.Pattern[str]"]] = []
        for cat in cats:
            for name, rx in _BUILTIN.get(cat, []):
                self._patterns.append((cat, name, rx))
        for cat, items in (custom_patterns or {}).items():
            for name, pat in items:
                self._patterns.append((cat, name, re.compile(pat)))
        self.on_violation = on_violation

    def scan(self, text: str, context: str = "") -> DLPResult:
        """Scan ``text``; return a :class:`DLPResult` with a redacted copy."""
        matches: list[DLPMatch] = []
        redacted = text
        for cat, name, rx in self._patterns:
            for m in rx.finditer(text):
                value = m.group(0)
                if name == "credit_card" and not _luhn_ok(value):
                    continue  # reduce false positives on random digit runs
                matches.append(DLPMatch(category=cat, pattern_name=name, masked_snippet=mask(value)))
                redacted = redacted.replace(value, f"[REDACTED:{name}]")

        clean = not matches
        result = DLPResult(clean=clean, matches=matches, redacted_text=redacted)
        if not clean:
            # Log category + pattern names only — never the matched value.
            cats = sorted({m.category for m in matches})
            names = sorted({m.pattern_name for m in matches})
            logger.warning(
                "DLP found %d match(es) [categories=%s names=%s]%s",
                len(matches),
                ",".join(cats),
                ",".join(names),
                f" context={context}" if context else "",
            )
            if self.on_violation:
                self.on_violation(result)
        return result

    def redact(self, text: str, context: str = "") -> str:
        """Always return safe (redacted) text. Never raises."""
        return self.scan(text, context=context).redacted_text

    def assert_clean(self, text: str, context: str = "") -> str:
        """Return the text unchanged if clean, else raise :class:`ValueError`."""
        result = self.scan(text, context=context)
        if not result.clean:
            names = ", ".join(sorted({m.pattern_name for m in result.matches}))
            raise ValueError(
                f"DLPScanner blocked text (LLM02:2026 / DSGAI01): detected {names}"
            )
        return text
