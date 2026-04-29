#!/usr/bin/env python3
"""CLI wrapper for the solver module.

Usage:
    uv run python scripts/solve-issues.py --issues 236,237,238
    uv run python scripts/solve-issues.py --group security-trust
    uv run python scripts/solve-issues.py --issues 236 --model google/gemma-3-27b-it:free
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from eedom.core.solver import (
    ModelSpec,
    ModelTier,
    SolverConfig,
    SolverResult,
    SolverTask,
    TaskStatus,
    solve_batch,
)


def _gh(*args: str) -> str:
    env = {**os.environ}
    env.pop("GITHUB_TOKEN", None)
    r = subprocess.run(
        ["gh", *args],
        capture_output=True,
        text=True,
        env=env,
        timeout=30,
    )
    if r.returncode != 0:
        print(f"gh error: {r.stderr}", file=sys.stderr)
        sys.exit(1)
    return r.stdout.strip()


def fetch_issues(numbers: list[int]) -> list[dict]:
    issues = []
    for n in numbers:
        raw = _gh(
            "issue",
            "view",
            str(n),
            "--json",
            "number,title,body,labels",
        )
        issues.append(json.loads(raw))
    return issues


def fetch_issues_by_label(label: str) -> list[dict]:
    raw = _gh(
        "issue",
        "list",
        "--label",
        label,
        "--state",
        "open",
        "--limit",
        "50",
        "--json",
        "number,title,body,labels",
    )
    return json.loads(raw)


def _extract_source_paths(body: str) -> list[str]:
    import re

    matches = re.findall(r"(?:src/eedom/[\w/]+\.py|policies/[\w/]+\.rego)", body)
    paths = [m.split(":")[0] for m in matches]
    return list(dict.fromkeys(paths))


def _read_file_safe(path: str) -> str:
    p = Path(path)
    if p.exists() and p.stat().st_size < 50_000:
        return p.read_text()
    return ""


def _resolve_parent_bug(body: str) -> dict | None:
    import re

    match = re.search(r"Parent bug:\s*#(\d+)", body)
    if not match:
        return None
    parent_num = match.group(1)
    raw = _gh("issue", "view", parent_num, "--json", "number,title,body")
    return json.loads(raw)


def issue_to_task(issue: dict) -> SolverTask:
    body = issue.get("body", "")
    combined_body = body

    parent = _resolve_parent_bug(body)
    if parent:
        combined_body = (
            f"## Detector Task\n{body}\n\n"
            f"## Parent Bug #{parent['number']}: {parent['title']}\n"
            f"{parent['body']}"
        )

    source_text = parent["body"] if parent else body
    source_paths = _extract_source_paths(source_text)
    source_files = {}
    test_files = {}

    for sp in source_paths:
        content = _read_file_safe(sp)
        if content:
            source_files[sp] = content
            test_name = sp.replace("src/eedom/", "tests/unit/test_")
            test_content = _read_file_safe(test_name)
            if test_content:
                test_files[test_name] = test_content

    labels = [lbl["name"] for lbl in issue.get("labels", [])]
    group = next((lbl for lbl in labels if lbl.startswith("group:")), "")

    return SolverTask(
        issue_number=issue["number"],
        title=issue["title"],
        body=combined_body,
        group=group,
        source_files=source_files,
        test_files=test_files,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Solve issues via LLM")
    parser.add_argument(
        "--issues",
        type=str,
        help="Comma-separated issue numbers",
    )
    parser.add_argument(
        "--group",
        type=str,
        help="Group label (e.g. security-trust)",
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="Override model (skips ladder)",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help="Seconds between requests (default 3)",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".temp/solver-results",
        help="Output directory",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Build prompts but don't send to API",
    )
    args = parser.parse_args()

    api_key = os.environ.get("OPENROUTER_EEDOM", "")
    if not api_key and not args.dry_run:
        print("OPENROUTER_EEDOM env var required", file=sys.stderr)
        sys.exit(1)

    if args.issues:
        numbers = [int(n.strip()) for n in args.issues.split(",")]
        issues = fetch_issues(numbers)
    elif args.group:
        label = f"group:{args.group}"
        issues = fetch_issues_by_label(label)
    else:
        parser.error("--issues or --group required")
        return

    tasks = [issue_to_task(i) for i in issues]

    if not tasks:
        print("No issues found")
        return

    print(f"Loaded {len(tasks)} tasks:")
    for t in tasks:
        src = len(t.source_files)
        print(f"  #{t.issue_number}: {t.title} ({src} source files)")

    if args.dry_run:
        from eedom.core.solver import build_prompt

        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for t in tasks:
            prompt = build_prompt(t)
            path = out / f"prompt_{t.issue_number}.md"
            path.write_text(prompt)
            print(f"  Wrote {path} ({len(prompt)} chars)")
        return

    config = SolverConfig(
        api_key=api_key,
        output_dir=args.output_dir,
        request_delay=args.delay,
    )

    if args.model:
        config.model_ladder = [
            ModelSpec(id=args.model, tier=ModelTier.DENSE),
        ]

    def on_result(r: SolverResult) -> None:
        icon = "✓" if r.status == TaskStatus.SUCCESS else "✗"
        model = r.model_used or "none"
        print(f"  {icon} #{r.issue_number}: {r.status} ({model}, {r.duration_s}s)")

    results = solve_batch(tasks, config, on_result=on_result)

    succeeded = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
    print(f"\nDone: {succeeded}/{len(results)} succeeded")

    manifest = Path(args.output_dir) / "manifest.json"
    manifest.write_text(
        json.dumps(
            [
                {
                    "issue": r.issue_number,
                    "status": r.status,
                    "model": r.model_used,
                    "file": (
                        f"test_detector_{r.issue_number}.py"
                        if r.status == TaskStatus.SUCCESS
                        else None
                    ),
                }
                for r in results
            ],
            indent=2,
        )
    )
    print(f"Manifest: {manifest}")


if __name__ == "__main__":
    main()
