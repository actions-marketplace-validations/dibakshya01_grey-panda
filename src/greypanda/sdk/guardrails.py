"""
guardrails.py — input and output guardrails for LLM calls.

Addresses:
    * LLM01:2026 Prompt Injection        (input side)
    * LLM10:2026 Improper Output Handling (output side, e.g. XSS / SSRF)
    * LLM02:2026 Sensitive Information Disclosure (ASCII-smuggling exfil channels)
    * AISVS C2  Input Validation
    * AISVS C7  Model Behavior, Output Control & Safety Assurance

Design honesty (see WHAT_IT_CAN_AND_CANNOT_DO.md):
    Pattern matching CANNOT stop all prompt injection. It blocks *known* patterns
    cheaply at the edge so that the expensive, deeper controls (data quarantine,
    least-privilege agents, audit) are not the only line of defence. Treat this as
    the first layer of defence in depth, never as "injection-proof".
"""

from __future__ import annotations

import html as _html
import logging
import re
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass, field

logger = logging.getLogger("greypanda.guardrails")

# --------------------------------------------------------------------------- #
# Invisible / control Unicode handling.
#
# Two tiers so we don't reject legitimate text:
#   * DANGEROUS  — no legitimate use in normal input (bidi overrides/isolates and
#     Unicode "tag" characters). Stripped AND flagged as a violation (blocks in
#     strict mode). This is the real "Trojan Source" / ASCII-smuggling surface.
#   * STRIP_SILENT — benign-but-unwanted (stray control chars, zero-width space,
#     BOM, word-joiner). Stripped silently, never a violation.
#
# IMPORTANT: ZWJ (U+200D) and ZWNJ (U+200C) are deliberately in NEITHER set —
# they are essential in emoji sequences (e.g. 👨‍👩‍👧) and Indic scripts, so we
# leave them untouched. Blocking or stripping them would corrupt valid input.
# --------------------------------------------------------------------------- #
_DANGEROUS_INVISIBLE = [
    (0x202A, 0x202E),    # bidirectional overrides ("Trojan Source")
    (0x2066, 0x2069),    # bidirectional isolates
    (0xE0000, 0xE007F),  # Unicode "tag" characters (ASCII smuggling)
]
_STRIP_SILENT = [
    (0x0000, 0x0008),    # C0 controls (keep \t \n \r)
    (0x000B, 0x000C),
    (0x000E, 0x001F),
    (0x007F, 0x009F),    # DEL + C1 controls
    (0x200B, 0x200B),    # zero-width space
    (0x200E, 0x200F),    # LTR/RTL marks
    (0x2060, 0x2064),    # word joiner / invisible math operators
    (0x206A, 0x206F),    # deprecated format characters
    (0xFEFF, 0xFEFF),    # BOM / zero-width no-break space
]

# Baseline injection patterns. These are intentionally broad and case-insensitive.
# Every adopter should extend this via ``extra_patterns`` for their own domain.
_BASELINE_PATTERNS: tuple[str, ...] = (
    r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+instructions",
    r"disregard\s+(?:your\s+)?(?:system\s+prompt|previous\s+instructions|rules)",
    r"forget\s+(?:everything|all|your\s+instructions)",
    # role override attempts ("you are now X" where X is an unexpected persona)
    r"you\s+are\s+now\s+(?!a\s+helpful|helpful\b)",
    r"act\s+as\s+(?:if\s+you\s+are|though\s+you\s+are)\b",
    r"pretend\s+(?:to\s+be|you\s+are)\b",
    r"\b(?:jailbreak|dan\s+mode|do\s+anything\s+now|developer\s+mode\s+enabled)\b",
    r"enable\s+developer\s+mode",
    # fake system framing / tag injection
    r"\[/?\s*system\s*\]",
    r"<\s*/?\s*system\s*>",
    r"###\s*system",
    r"<!--.*?(?:instruction|system|ignore).*?-->",
    # instruction to reveal the system prompt / hidden context (LLM08)
    r"(?:reveal|print|repeat|show|output)\s+(?:your\s+)?(?:system\s+prompt|initial\s+instructions|hidden\s+(?:context|prompt))",  # grey-panda: ignore (signature pattern, not a real log call)
    r"what\s+(?:were|are)\s+your\s+(?:original\s+)?instructions",
    # summarise-everything extraction
    r"summar(?:ize|ise)\s+everything\s+(?:you(?:'ve| have)\s+been\s+told|above)",
)

_MAX_INPUT_CHARS = 50_000

# markdown / html image to an external domain: a classic silent-exfil channel
# where the "URL" carries stolen data to an attacker-controlled host on render.
_MD_IMAGE = re.compile(r"!\[[^\]]*\]\(\s*(https?://[^)\s]+)\s*\)", re.IGNORECASE)
_HTML_IMAGE = re.compile(r"<img\b[^>]*\bsrc\s*=\s*[\"']?(https?://[^\"'>\s]+)", re.IGNORECASE)
_LINK_URL = re.compile(r"\]\(\s*(https?://[^)\s]+)\s*\)", re.IGNORECASE)
_DANGEROUS_SQL = re.compile(
    r"\b(?:DROP|DELETE|TRUNCATE|UPDATE|INSERT|ALTER|GRANT)\b\s", re.IGNORECASE
)

# Common XSS constructs in model output. These are neutralised (not a full HTML
# sanitiser — see the OutputGuardrail docstring).
_SCRIPT_BLOCK = re.compile(r"<\s*script\b[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL)
_BARE_SCRIPT = re.compile(r"<\s*/?\s*script\b[^>]*>", re.IGNORECASE)
_EVENT_ATTR = re.compile(r"\son[a-z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.IGNORECASE)
_JS_URI = re.compile(r"(?:javascript|vbscript|data)\s*:(?=[^\s\"']*(?:script|alert|onerror|base64|text/html))", re.IGNORECASE)
_EMBED_TAG = re.compile(r"<\s*(?:iframe|object|embed|form|base|meta|link)\b[^>]*>", re.IGNORECASE)


@dataclass
class GuardrailResult:
    """Outcome of a guardrail check.

    Attributes:
        passed: ``True`` when no violation was found.
        violations: Human-readable descriptions of each violation (never raw
            secret values — safe to log and to surface in reports).
        sanitized_text: A cleaned copy of the text (invisible characters stripped,
            unsafe fragments neutralised). ``None`` only if sanitisation is N/A.
    """

    passed: bool
    violations: list[str] = field(default_factory=list)
    sanitized_text: str | None = None


def _strip_invisible(text: str) -> tuple[str, bool]:
    """Strip invisible characters. Returns (clean_text, removed_dangerous).

    ``removed_dangerous`` is ``True`` only when a genuinely-dangerous character
    (bidi override/isolate or Unicode tag char) was removed — benign zero-width
    characters are stripped silently and do not set the flag. ZWJ/ZWNJ are left
    untouched so emoji sequences and Indic scripts survive.
    """
    out = []
    removed_dangerous = False
    for ch in text:
        cp = ord(ch)
        if any(lo <= cp <= hi for lo, hi in _DANGEROUS_INVISIBLE):
            removed_dangerous = True
            continue
        if any(lo <= cp <= hi for lo, hi in _STRIP_SILENT):
            continue
        out.append(ch)
    return "".join(out), removed_dangerous


class PromptGuardrail:
    """Run before every LLM call on raw, untrusted input.

    The secure path is the easy path: one ``assert_safe`` call in front of your
    existing prompt building is enough to block the known-bad baseline.

    Args:
        extra_patterns: Additional org/domain-specific injection regexes. These
            are compiled case-insensitively and added to the baseline set.
        strict: When ``True`` (default) a violation raises from ``assert_safe``.
            When ``False`` violations are logged and returned but not blocking —
            useful for a monitor-only rollout before you enforce.
        max_chars: Reject inputs longer than this (defends LLM06 Unbounded
            Consumption / oversized-prompt abuse). Defaults to 50,000.
    """

    def __init__(
        self,
        extra_patterns: Iterable[str] | None = None,
        strict: bool = True,
        max_chars: int = _MAX_INPUT_CHARS,
    ) -> None:
        self.strict = strict
        self.max_chars = max_chars
        raw = list(_BASELINE_PATTERNS) + list(extra_patterns or [])
        self._patterns: list[re.Pattern[str]] = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in raw
        ]

    def check(self, text: str, source: str = "user") -> GuardrailResult:
        """Check ``text`` and return a :class:`GuardrailResult` (never raises)."""
        violations: list[str] = []

        # 1. Normalise + strip invisible characters. Only genuinely-dangerous
        #    invisibles (bidi overrides / tag chars) count as a violation; benign
        #    zero-width characters are stripped silently so ordinary text — and
        #    emoji/Indic scripts using ZWJ — is never rejected.
        normalised = unicodedata.normalize("NFKC", text)
        cleaned, removed_dangerous = _strip_invisible(normalised)
        if removed_dangerous:
            violations.append(
                "dangerous bidi/tag Unicode removed (Trojan Source / ASCII smuggling)"
            )

        # 2. Length / unbounded-consumption guard.
        if len(cleaned) > self.max_chars:
            violations.append(
                f"input exceeds max length ({len(cleaned)} > {self.max_chars} chars)"
            )

        # 3. Known injection patterns.
        for pat in self._patterns:
            if pat.search(cleaned):
                violations.append(f"matched injection pattern: /{pat.pattern}/")

        passed = not violations
        if not passed:
            # Log the pattern names only — never the raw input.
            logger.warning(
                "PromptGuardrail flagged input from source=%s (%d violation(s))",
                source,
                len(violations),
            )
        return GuardrailResult(passed=passed, violations=violations, sanitized_text=cleaned)

    def assert_safe(self, text: str, source: str = "user") -> str:
        """Return sanitised text, or raise :class:`ValueError` in strict mode."""
        result = self.check(text, source=source)
        if not result.passed and self.strict:
            raise ValueError(
                "PromptGuardrail blocked input (LLM01:2026 Prompt Injection): "
                + "; ".join(result.violations)
            )
        return result.sanitized_text or ""


class OutputGuardrail:
    """Run on LLM output before rendering it or passing it downstream.

    Addresses LLM10:2026 (Improper Output Handling) and LLM02:2026 (silent data
    theft through image/link URLs to attacker-controlled domains).

    What it does, precisely (so you can trust the boundary):

    * **Rewrites external-image exfil URLs** (markdown + HTML ``<img>``) to domains
      outside ``allowed_url_domains``.
    * **Neutralises the most common XSS constructs** when ``block_dangerous_html``
      is on (default): ``<script>`` blocks, inline event handlers (``onerror=`` …),
      ``javascript:``/``vbscript:``/``data:text/html`` URIs, and it flags embedding
      tags (``<iframe>``/``<object>``/``<embed>``). Each is reported as a violation.
    * Optionally flags destructive SQL verbs (``block_sql_in_output``).

    What it is **NOT**: a complete HTML sanitiser. It reduces risk (defense in
    depth) but does not guarantee XSS-safe HTML. **If you render untrusted model
    output as HTML, set ``escape_html=True``** (returns ``html.escape``-d text,
    which is safe to display as text), or rely on your framework's autoescaping or
    a vetted sanitiser (e.g. ``bleach``, DOMPurify). See WHAT_IT_CAN_AND_CANNOT_DO.md.

    Args:
        block_external_images: Rewrite external image URLs. Default ``True``.
        block_dangerous_html: Neutralise script/event-handler/js-URI XSS
            constructs and flag embed tags. Default ``True``.
        escape_html: If ``True``, HTML-escape the entire output (the safe choice
            when the output will be rendered as HTML). Overrides the other
            neutralisation (there is nothing left to neutralise once escaped).
            Default ``False``.
        block_sql_in_output: Flag destructive SQL verbs. Default ``False``.
        allowed_url_domains: Domains considered safe for image URLs. ``None`` means
            no external domain is allowed (all external images are rewritten).
    """

    def __init__(
        self,
        block_external_images: bool = True,
        block_dangerous_html: bool = True,
        escape_html: bool = False,
        block_sql_in_output: bool = False,
        allowed_url_domains: list[str] | None = None,
    ) -> None:
        self.block_external_images = block_external_images
        self.block_dangerous_html = block_dangerous_html
        self.escape_html = escape_html
        self.block_sql_in_output = block_sql_in_output
        self.allowed_url_domains = [d.lower() for d in (allowed_url_domains or [])]

    def _is_external(self, url: str) -> bool:
        host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0].lower()
        host = host.split("@")[-1].split(":")[0]  # strip userinfo + port
        if not self.allowed_url_domains:
            return True
        return not any(
            host == d or host.endswith("." + d) for d in self.allowed_url_domains
        )

    def sanitize(self, output: str) -> GuardrailResult:
        """Return a :class:`GuardrailResult` with a neutralised ``sanitized_text``."""
        violations: list[str] = []
        text = output

        # Safest mode: escape everything. Nothing renders as active HTML.
        if self.escape_html:
            escaped = _html.escape(output)
            if _SCRIPT_BLOCK.search(output) or _EVENT_ATTR.search(output) or _JS_URI.search(output):
                violations.append("HTML-escaped output containing active markup (XSS constructs)")
            return GuardrailResult(passed=True, violations=violations, sanitized_text=escaped)

        if self.block_external_images:
            def _repl_md(m: re.Match[str]) -> str:
                url = m.group(1)
                if self._is_external(url):
                    violations.append(f"blocked external markdown image URL: {_host(url)}")
                    return "[image removed by Grey Panda: external URL]"
                return m.group(0)

            def _repl_html(m: re.Match[str]) -> str:
                url = m.group(1)
                if self._is_external(url):
                    violations.append(f"blocked external HTML image URL: {_host(url)}")
                    return "[image removed by Grey Panda: external URL]"
                return m.group(0)

            text = _MD_IMAGE.sub(_repl_md, text)
            text = _HTML_IMAGE.sub(_repl_html, text)

        if self.block_dangerous_html:
            if _SCRIPT_BLOCK.search(text) or _BARE_SCRIPT.search(text):
                violations.append("neutralised <script> in model output")
                text = _SCRIPT_BLOCK.sub("[script removed by Grey Panda]", text)
                text = _BARE_SCRIPT.sub("[script removed by Grey Panda]", text)
            if _EVENT_ATTR.search(text):
                violations.append("stripped inline event handler(s) (on*=) in model output")
                text = _EVENT_ATTR.sub("", text)
            if _JS_URI.search(text):
                violations.append("neutralised javascript:/data: URI in model output")
                text = _JS_URI.sub("blocked:", text)
            if _EMBED_TAG.search(text):
                violations.append("embedding tag (iframe/object/embed/…) present in model output")
                text = _EMBED_TAG.sub("[embed removed by Grey Panda]", text)

        if self.block_sql_in_output and _DANGEROUS_SQL.search(text):
            violations.append("destructive SQL verb present in model output")

        passed = not violations
        if not passed:
            logger.warning(
                "OutputGuardrail neutralised model output (%d violation(s))",
                len(violations),
            )
        return GuardrailResult(passed=passed, violations=violations, sanitized_text=text)

    def assert_safe(self, output: str) -> str:
        """Return sanitised output text (never raises — output is always cleaned)."""
        return self.sanitize(output).sanitized_text or ""


def _host(url: str) -> str:
    host = re.sub(r"^https?://", "", url, flags=re.IGNORECASE).split("/")[0]
    return host.split("@")[-1]
