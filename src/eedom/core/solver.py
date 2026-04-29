# tested-by: tests/unit/test_solver.py
"""Issue solver — generates detector tests via LLM with model fallback.

API-style module for automated issue resolution. Reads GitHub issue context,
builds scoped prompts, sends to OpenRouter-compatible endpoints with rate-limit
aware sequential processing and model fallback ladder.

Public interface:
  - SolverConfig     — model ladder, rate limits, endpoint
  - SolverTask       — structured task from a GitHub issue
  - SolverResult     — result from model (code + metadata)
  - solve()          — process a single task
  - solve_batch()    — process multiple tasks sequentially with rate limiting
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path

import httpx
import structlog

logger = structlog.get_logger()


class ModelTier(StrEnum):
    DENSE = "dense"
    MOE = "moe"
    MOE_LARGE = "moe_large"


@dataclass
class ModelSpec:
    id: str
    tier: ModelTier
    context_window: int = 32_000
    max_output: int = 8_000


DEFAULT_MODEL_LADDER: list[ModelSpec] = [
    ModelSpec(id="google/gemma-3-27b-it:free", tier=ModelTier.DENSE, context_window=96_000),
    ModelSpec(id="qwen/qwen3-235b-a22b:free", tier=ModelTier.MOE, context_window=40_000),
    ModelSpec(id="mistralai/devstral-small:free", tier=ModelTier.MOE_LARGE, context_window=128_000),
]


@dataclass
class SolverConfig:
    endpoint: str = "https://openrouter.ai/api"
    api_key: str = ""
    model_ladder: list[ModelSpec] = field(default_factory=lambda: list(DEFAULT_MODEL_LADDER))
    output_dir: str = ".temp/solver-results"
    request_delay: float = 2.0
    max_retries: int = 3
    timeout: int = 120


class TaskStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


@dataclass
class SolverTask:
    issue_number: int
    title: str
    body: str
    group: str = ""
    source_files: dict[str, str] = field(default_factory=dict)
    test_files: dict[str, str] = field(default_factory=dict)


@dataclass
class SolverResult:
    issue_number: int
    status: TaskStatus
    model_used: str = ""
    code: str = ""
    error: str = ""
    attempts: int = 0
    duration_s: float = 0.0


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}

SYSTEM_PROMPT = """\
You are a senior test engineer writing deterministic detection tests for known \
bugs in a Python codebase called eedom (Eagle Eyed Dom — a CI code review tool).

Your output is ONLY raw Python code. No markdown, no code fences, no explanation.
Start with imports. End with the last test function.

Conventions you MUST follow:
- pytest as the test framework
- structlog for logging (never print)
- Typed annotations on all functions
- One test class per detection rule, named Test{BugDescription}
- Each test must FAIL on the current buggy code (RED phase)
- Use unittest.mock for isolation, never hit real APIs or filesystem
- Descriptive test names: test_{what}_{condition}_{expected}
- Add a module docstring: "Detector test for issue #{number}"
"""


def build_prompt(task: SolverTask) -> str:
    sections = [f"# Issue #{task.issue_number}: {task.title}\n\n{task.body}"]

    if task.source_files:
        sections.append("# Source Files Under Test")
        for path, content in task.source_files.items():
            sections.append(f"\n## {path}\n```python\n{content}\n```")

    if task.test_files:
        sections.append("# Existing Tests (match these conventions)")
        for path, content in task.test_files.items():
            truncated = "\n".join(content.split("\n")[:80])
            sections.append(f"\n## {path}\n```python\n{truncated}\n```")

    sections.append(
        "# Task\n\n"
        f"Write a pytest test module that detects the bug in issue #{task.issue_number}.\n\n"
        "Requirements:\n"
        "1. The test MUST fail on the current codebase (this is the RED phase)\n"
        "2. The test verifies the specific behavior described in the bug\n"
        "3. Use mock/patch to isolate from external dependencies\n"
        "4. Match the test conventions shown in existing tests above\n"
        "5. Include the tested-by comment: # tested-by: tests/unit/test_detector_{issue}.py\n\n"
        "Output ONLY the Python code. No markdown, no explanation."
    )

    return "\n\n".join(sections)


def _extract_rate_limit(headers: httpx.Headers) -> float | None:
    remaining = headers.get("x-ratelimit-remaining")
    reset = headers.get("x-ratelimit-reset")
    if remaining is not None and int(remaining) < 2 and reset is not None:
        wait = max(0, int(reset) - int(time.time()))
        return float(wait + 1)
    return None


def _post(
    client: httpx.Client,
    url: str,
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int,
    timeout: int,
) -> tuple[str, dict]:
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/gitrdunhq/eedom",
        "X-Title": "eedom-solver",
    }
    payload = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": 0.2,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
    }
    resp = client.post(url, json=payload, headers=headers, timeout=timeout)
    return resp.text, {
        "status": resp.status_code,
        "headers": dict(resp.headers),
        "rate_limit_remaining": resp.headers.get("x-ratelimit-remaining"),
    }


def solve(task: SolverTask, config: SolverConfig) -> SolverResult:
    """Solve a single task, trying each model in the ladder."""
    start = time.monotonic()
    prompt = build_prompt(task)
    url = f"{config.endpoint}/v1/chat/completions"
    attempts = 0

    with httpx.Client() as client:
        for model_spec in config.model_ladder:
            for retry in range(config.max_retries):
                attempts += 1
                try:
                    raw, meta = _post(
                        client=client,
                        url=url,
                        api_key=config.api_key,
                        model=model_spec.id,
                        system=SYSTEM_PROMPT,
                        user=prompt,
                        max_tokens=model_spec.max_output,
                        timeout=config.timeout,
                    )
                except (httpx.TimeoutException, httpx.HTTPError) as exc:
                    logger.warning(
                        "solver.request_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        error=str(exc),
                        attempt=attempts,
                    )
                    time.sleep(2.0**retry)
                    continue

                status_code = meta["status"]

                if status_code == 429:
                    wait = _extract_rate_limit(httpx.Headers(meta["headers"])) or (2.0**retry * 5)
                    logger.warning(
                        "solver.rate_limited",
                        issue=task.issue_number,
                        model=model_spec.id,
                        wait_s=wait,
                    )
                    time.sleep(wait)
                    continue

                if status_code in _RETRYABLE_STATUS:
                    logger.warning(
                        "solver.retryable",
                        issue=task.issue_number,
                        model=model_spec.id,
                        status=status_code,
                        attempt=attempts,
                    )
                    time.sleep(2.0**retry)
                    continue

                if status_code != 200:
                    logger.warning(
                        "solver.api_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        status=status_code,
                        body=raw[:200],
                    )
                    break

                try:
                    import orjson

                    data = orjson.loads(raw)
                    code = data["choices"][0]["message"]["content"]
                except (KeyError, IndexError, TypeError) as exc:
                    logger.warning(
                        "solver.parse_error",
                        issue=task.issue_number,
                        model=model_spec.id,
                        error=str(exc),
                    )
                    break

                code = _clean_code(code)
                if not _looks_like_python(code):
                    logger.warning(
                        "solver.invalid_output",
                        issue=task.issue_number,
                        model=model_spec.id,
                        preview=code[:100],
                    )
                    break

                duration = time.monotonic() - start
                logger.info(
                    "solver.success",
                    issue=task.issue_number,
                    model=model_spec.id,
                    code_lines=code.count("\n") + 1,
                    duration_s=round(duration, 1),
                )
                return SolverResult(
                    issue_number=task.issue_number,
                    status=TaskStatus.SUCCESS,
                    model_used=model_spec.id,
                    code=code,
                    attempts=attempts,
                    duration_s=round(duration, 1),
                )

    duration = time.monotonic() - start
    return SolverResult(
        issue_number=task.issue_number,
        status=TaskStatus.FAILED,
        error="All models exhausted",
        attempts=attempts,
        duration_s=round(duration, 1),
    )


def solve_batch(
    tasks: list[SolverTask],
    config: SolverConfig,
    on_result: callable | None = None,
) -> list[SolverResult]:
    """Process tasks sequentially with rate-limit pacing.

    Calls on_result(result) after each task if provided (webhook hook point).
    """
    results: list[SolverResult] = []
    out_dir = Path(config.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    for i, task in enumerate(tasks):
        logger.info(
            "solver.batch_progress",
            current=i + 1,
            total=len(tasks),
            issue=task.issue_number,
        )

        result = solve(task, config)
        results.append(result)

        if result.status == TaskStatus.SUCCESS:
            out_path = out_dir / f"test_detector_{task.issue_number}.py"
            out_path.write_text(result.code)
            logger.info("solver.wrote_file", path=str(out_path))

        if on_result is not None:
            on_result(result)

        if i < len(tasks) - 1:
            time.sleep(config.request_delay)

    succeeded = sum(1 for r in results if r.status == TaskStatus.SUCCESS)
    failed = sum(1 for r in results if r.status == TaskStatus.FAILED)
    logger.info("solver.batch_complete", succeeded=succeeded, failed=failed, total=len(tasks))

    return results


def _clean_code(raw: str) -> str:
    lines = raw.strip().split("\n")
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _looks_like_python(code: str) -> bool:
    if not code:
        return False
    indicators = ["import ", "def test_", "class Test", "from ", "assert "]
    return any(indicator in code for indicator in indicators)
