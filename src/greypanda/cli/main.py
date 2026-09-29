"""
main.py — the ``greypanda`` / ``gp`` command-line interface.

Subcommands:
    gp scan       Scan code for AI/agent/MCP security issues (md/json/sarif).
    gp init       Scaffold Grey Panda into a repo (config, CI, pre-commit, checklist).
    gp verify     Verify against AISVS Level 1/2/3 and produce a report.
    gp checklist  Print the AI security checklist.
    gp standards  List / explain the standards and control IDs.
    gp agbom      Emit an Agent Bill of Materials.
    gp mcp        Run Grey Panda as an MCP server (stdio).
    gp doctor     Environment self-check and honest-limits pointer.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from .._version import __version__
from ..scanner.engine import AISecurityScanner, exceeds_threshold, severity_counts
from ..scanner.reporters import report_json, report_markdown, report_sarif
from ..scanner.profiles import DEFAULT_PROFILE, PROFILES, get_profile

PANDA = "🐼"


def _print(msg: str = "") -> None:
    sys.stdout.write(msg + "\n")


# --------------------------------------------------------------------------- #
# scan
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace) -> int:
    profile = get_profile(args.profile)
    fail_on = (args.fail_on or profile.default_fail_on).upper()
    scanner = AISecurityScanner(profile=args.profile)

    start = time.time()
    findings = scanner.scan_path(Path(args.path))
    elapsed = time.time() - start

    if args.format == "json":
        out = report_json(findings, args.path, elapsed, args.profile)
    elif args.format == "sarif":
        out = report_sarif(findings, args.path, elapsed, args.profile)
    else:
        out = report_markdown(findings, args.path, elapsed, args.profile)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        counts = severity_counts(findings)
        _print(f"{PANDA} Grey Panda scanned '{args.path}' [{args.profile}] in {elapsed:.2f}s")
        _print(f"   {counts['CRITICAL']} critical · {counts['HIGH']} high · "
               f"{counts['MEDIUM']} medium · {counts['LOW']} low → {args.output}")
    else:
        _print(out)

    if exceeds_threshold(findings, fail_on):
        # Send the gate message to stderr so it never corrupts json/sarif stdout.
        sys.stderr.write(f"{PANDA} FAIL: findings at or above {fail_on}. Fix them, or lower --fail-on.\n")
        return 1
    return 0


# --------------------------------------------------------------------------- #
# init
# --------------------------------------------------------------------------- #
_CONFIG_TEMPLATE = """# Grey Panda configuration — https://github.com/greypanda/grey-panda
[greypanda]
profile = "{profile}"     # solo | team | enterprise
fail_on = "{fail_on}"     # CRITICAL | HIGH | MEDIUM | LOW
paths = ["."]
"""

_PRECOMMIT_TEMPLATE = """# Add to your .pre-commit-config.yaml (https://pre-commit.com)
repos:
  - repo: local
    hooks:
      - id: grey-panda
        name: Grey Panda AI security scan
        entry: gp scan --profile {profile} --fail-on {fail_on}
        language: system
        pass_filenames: false
"""

_WORKFLOW_TEMPLATE = """name: Grey Panda AI Security Scan
on:
  pull_request:
    branches: [main, master, "release/**"]
  push:
    branches: [main, master]
permissions:
  contents: read
  pull-requests: write
  security-events: write
jobs:
  grey-panda:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install Grey Panda
        run: pip install grey-panda
      - name: Scan (SARIF for code scanning)
        run: gp scan --profile {profile} --format sarif --output grey-panda.sarif --fail-on {fail_on}
        continue-on-error: true
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: grey-panda.sarif
      - name: Scan (Markdown report, enforce gate)
        run: gp scan --profile {profile} --fail-on {fail_on}
"""


def cmd_init(args: argparse.Namespace) -> int:
    profile = get_profile(args.profile)
    fail_on = profile.default_fail_on
    root = Path(args.path)
    created: list[str] = []

    def write(rel: str, content: str) -> None:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and not args.force:
            _print(f"   skip (exists): {rel}  (use --force to overwrite)")
            return
        target.write_text(content, encoding="utf-8")
        created.append(rel)

    write(".greypanda.toml", _CONFIG_TEMPLATE.format(profile=args.profile, fail_on=fail_on))
    write(".github/workflows/grey-panda.yml", _WORKFLOW_TEMPLATE.format(profile=args.profile, fail_on=fail_on))
    write("greypanda-precommit.snippet.yaml", _PRECOMMIT_TEMPLATE.format(profile=args.profile, fail_on=fail_on))

    _print(f"{PANDA} Grey Panda initialised in '{root}' [{args.profile}]")
    for c in created:
        _print(f"   + {c}")
    _print("")
    _print("Next: run `gp scan` to see your first report, then `gp checklist`.")
    return 0


# --------------------------------------------------------------------------- #
# verify
# --------------------------------------------------------------------------- #
def cmd_verify(args: argparse.Namespace) -> int:
    from ..verify.aisvs import verify_aisvs, report_markdown as verify_md

    report = verify_aisvs(args.path, level=args.level, profile=args.profile)
    if args.format == "json":
        from dataclasses import asdict
        out = json.dumps({
            "level": report.level, "scan_path": report.scan_path, "timestamp": report.timestamp,
            "total": report.total, "passed": report.passed, "failed": report.failed,
            "attest": report.attest,
            "chapters": {k: [asdict(r) for r in v] for k, v in report.chapters.items()},
        }, indent=2)
    else:
        out = verify_md(report)

    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _print(f"{PANDA} AISVS L{args.level} verification → {args.output} "
               f"(✅ {report.passed} / ❌ {report.failed} / 📝 {report.attest})")
    else:
        _print(out)
    return 1 if report.failed else 0


# --------------------------------------------------------------------------- #
# checklist
# --------------------------------------------------------------------------- #
def cmd_checklist(args: argparse.Namespace) -> int:
    for parent in Path(__file__).resolve().parents:
        candidate = parent / "docs" / "AI_SECURITY_CHECKLIST.md"
        if candidate.exists():
            _print(candidate.read_text(encoding="utf-8"))
            return 0
    _print("Checklist not found next to the package. See "
           "https://github.com/greypanda/grey-panda/blob/main/docs/AI_SECURITY_CHECKLIST.md")
    return 0


# --------------------------------------------------------------------------- #
# standards
# --------------------------------------------------------------------------- #
def cmd_standards(args: argparse.Namespace) -> int:
    from ..data import all_standards, lookup

    if args.id:
        entry = lookup(args.id)
        if not entry:
            _print(f"No control found for '{args.id}'.")
            return 1
        _print(f"{entry['id']} — {entry['title']}  [{entry.get('_standard','')}]")
        _print("")
        _print(entry.get("description", ""))
        if entry.get("remediation"):
            _print(f"\nRemediation: {entry['remediation']}")
        if entry.get("grey_panda_controls"):
            _print("Grey Panda controls: " + ", ".join(entry["grey_panda_controls"]))
        if entry.get("scanner_rules"):
            _print("Scanner rules: " + ", ".join(entry["scanner_rules"]))
        return 0

    for key, doc in all_standards().items():
        _print(f"{doc.get('name', key)}  ({doc.get('version','')})")
        for c in doc.get("controls", []):
            _print(f"  {c['id']:<14} {c['title']}")
        _print("")
    return 0


# --------------------------------------------------------------------------- #
# agbom
# --------------------------------------------------------------------------- #
def cmd_agbom(args: argparse.Namespace) -> int:
    from ..sdk.acs import agent_bill_of_materials

    bom = agent_bill_of_materials(
        agent_id=args.agent_id,
        tools=args.tool or [],
        models=args.model or [],
        mcp_servers=args.mcp_server or [],
        data_sources=args.data_source or [],
        version=args.agent_version,
    )
    out = json.dumps(bom, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _print(f"{PANDA} AgBOM for '{args.agent_id}' → {args.output}")
    else:
        _print(out)
    return 0


# --------------------------------------------------------------------------- #
# mcp
# --------------------------------------------------------------------------- #
def cmd_mcp(args: argparse.Namespace) -> int:
    from ..mcpserver.server import serve_stdio

    serve_stdio()
    return 0


# --------------------------------------------------------------------------- #
# doctor
# --------------------------------------------------------------------------- #
def cmd_doctor(args: argparse.Namespace) -> int:
    from ..data import all_standards
    from ..scanner.rules import RULES

    _print(f"{PANDA} Grey Panda v{__version__}")
    _print(f"   Python: {sys.version.split()[0]}")
    _print(f"   Scanner rules: {len(RULES)}")
    ok = True
    try:
        docs = all_standards()
        total = sum(len(d.get("controls", [])) for d in docs.values())
        _print(f"   Standards pack: {len(docs)} documents, {total} controls  ✅")
    except Exception as exc:
        ok = False
        _print(f"   Standards pack: FAILED to load ({exc})  ❌")
    _print(f"   Profiles: {', '.join(PROFILES)}")
    _print("")
    _print("Honest limits: Grey Panda is static analysis + drop-in guardrails — a strong")
    _print("floor, not a ceiling. It cannot stop all prompt injection or novel attacks.")
    _print("See docs/WHAT_IT_CAN_AND_CANNOT_DO.md before you rely on it.")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gp",
        description=f"{PANDA} Grey Panda — the calm guardian for AI, agent, and MCP code.",
        epilog="Docs: https://github.com/greypanda/grey-panda",
    )
    p.add_argument("--version", action="version", version=f"Grey Panda {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    # scan
    s = sub.add_parser("scan", help="Scan code for AI/agent/MCP security issues.")
    s.add_argument("path", nargs="?", default=".", help="File or directory (default: .)")
    s.add_argument("--profile", choices=list(PROFILES), default=DEFAULT_PROFILE)
    s.add_argument("--format", choices=["markdown", "json", "sarif"], default="markdown")
    s.add_argument("--output", "-o", help="Write report to a file instead of stdout.")
    s.add_argument("--fail-on", choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
                   help="Exit 1 if any finding is at this severity or above "
                        "(default: the profile's threshold).")
    s.set_defaults(func=cmd_scan)

    # init
    i = sub.add_parser("init", help="Scaffold Grey Panda into a repo.")
    i.add_argument("path", nargs="?", default=".", help="Repo root (default: .)")
    i.add_argument("--profile", choices=list(PROFILES), default=DEFAULT_PROFILE)
    i.add_argument("--force", action="store_true", help="Overwrite existing files.")
    i.set_defaults(func=cmd_init)

    # verify
    v = sub.add_parser("verify", help="Verify against AISVS Level 1/2/3.")
    v.add_argument("path", nargs="?", default=".", help="File or directory (default: .)")
    v.add_argument("--level", type=int, choices=[1, 2, 3], default=1)
    v.add_argument("--profile", choices=list(PROFILES), default="enterprise")
    v.add_argument("--format", choices=["markdown", "json"], default="markdown")
    v.add_argument("--output", "-o", help="Write the report to a file.")
    v.set_defaults(func=cmd_verify)

    # checklist
    c = sub.add_parser("checklist", help="Print the AI security checklist.")
    c.set_defaults(func=cmd_checklist)

    # standards
    st = sub.add_parser("standards", help="List or explain standards / control IDs.")
    st.add_argument("id", nargs="?", help="A control ID to explain (e.g. LLM01:2026, C10, ASI02).")
    st.set_defaults(func=cmd_standards)

    # agbom
    a = sub.add_parser("agbom", help="Emit an Agent Bill of Materials (AgBOM).")
    a.add_argument("agent_id", help="Agent identifier / name.")
    a.add_argument("--tool", action="append", help="A tool the agent uses (repeatable).")
    a.add_argument("--model", action="append", help="A model the agent uses (repeatable).")
    a.add_argument("--mcp-server", action="append", help="An MCP server the agent uses (repeatable).")
    a.add_argument("--data-source", action="append", help="A data source (repeatable).")
    a.add_argument("--agent-version", default="0.0.0")
    a.add_argument("--output", "-o", help="Write the AgBOM to a file.")
    a.set_defaults(func=cmd_agbom)

    # mcp
    m = sub.add_parser("mcp", help="Run Grey Panda as an MCP server (stdio).")
    m.set_defaults(func=cmd_mcp)

    # doctor
    d = sub.add_parser("doctor", help="Environment self-check.")
    d.set_defaults(func=cmd_doctor)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, FileNotFoundError) as exc:
        _print(f"{PANDA} error: {exc}")
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
