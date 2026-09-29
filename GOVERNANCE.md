# Governance

Grey Panda is a community open-source project under a light, transparent governance
model. The goal is to keep the project trustworthy, standards-anchored, and easy to
contribute to.

## Roles
- **Users** — anyone using Grey Panda. Feedback and bug reports are contributions.
- **Contributors** — anyone whose PR has been merged.
- **Maintainers** — contributors with commit rights who review PRs, triage issues,
  cut releases, and steward the roadmap. Listed in [CODEOWNERS](.github/CODEOWNERS).

## Decision making
- Routine changes: lazy consensus. A PR with maintainer approval and green CI merges.
- Significant changes (new module, breaking change, new standard, changing the
  zero-dependency guarantee): open a discussion/issue first; needs sign-off from at
  least two maintainers.
- Disagreements are resolved by maintainer majority; the aim is always consensus.

## Principles that don't change lightly
These are the project's identity. Changing any of them requires a documented
discussion and broad maintainer agreement:
1. Zero runtime dependencies in the shipped package.
2. Every rule and control cites a specific standard ID.
3. Honesty about limits (the "Can and Cannot Do" doc stays current).
4. Same safety floor for every profile.

## Releases
Semantic versioning. Maintainers tag releases from `main`; the `CHANGELOG.md` records
every release.

## Becoming a maintainer
Sustained, high-quality contributions and good community judgment. Existing
maintainers nominate and confirm new ones.

## Standards stewardship
Grey Panda tracks the OWASP, AISVS, ACS, NIST, and related standards it cites. When
those standards publish new versions, updating the `standards/` pack and mappings is
a first-class, prioritised contribution.
