"""
profiles.py — Solo, Team, and Enterprise profiles.

Same safety floor for everyone; the profile scales the *process*, not the safety.
A profile decides which rules are active and the default severity that fails a
build. Solo stays quiet and high-signal so a single developer isn't drowned;
Enterprise turns on the full set and gates hard.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Profile:
    name: str
    description: str
    default_fail_on: str  # CRITICAL | HIGH | MEDIUM | LOW


PROFILES: dict[str, Profile] = {
    "solo": Profile(
        name="solo",
        description="Solo / indie developer. High-signal core rules, fail on CRITICAL. "
                    "No process overhead — just 'am I safe?'.",
        default_fail_on="CRITICAL",
    ),
    "team": Profile(
        name="team",
        description="Team / startup. Adds RAG isolation, no-raw-logging, MCP, and shadow-AI "
                    "rules; fails a build on HIGH and above.",
        default_fail_on="HIGH",
    ),
    "enterprise": Profile(
        name="enterprise",
        description="Enterprise / regulated. Every rule on, including MEDIUM advisories "
                    "(cost/consumption, memory-poisoning, and the DLP-before-call reminder) "
                    "that surface as notes; fails on HIGH and above.",
        default_fail_on="HIGH",
    ),
}

DEFAULT_PROFILE = "team"


def get_profile(name: str) -> Profile:
    try:
        return PROFILES[name]
    except KeyError:
        raise ValueError(
            f"unknown profile '{name}'. Choose from: {', '.join(PROFILES)}"
        ) from None
