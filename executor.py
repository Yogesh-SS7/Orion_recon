"""
executor.py

Owns the worker pool and per-tool rate limiters.  tools.py wrappers are
single-call and concurrency-unaware; all scheduling happens here.

Design:
  - ThreadPoolExecutor sized by scope.json constraints.max_concurrent_calls.
    Threads are appropriate because all work is subprocess I/O, not CPU.
  - Per-tool token-bucket rate limiter, keyed off
    scope.json.constraints.rate_limits.<tool>.max_requests_per_min.
    A single global bucket would either over-throttle passive tools or
    under-protect active scanners — per-tool is intentional.
  - run_batch() yields results AS EACH CALL COMPLETES, not after the full
    batch settles.  agent.py can start writing raw/parsed files immediately
    for fast calls without waiting for slow ones.
  - Per-call timeouts are unchanged by the pool — they are enforced inside
    each tool wrapper in tools.py.

Non-goals (explicitly deferred):
  - asyncio — ThreadPoolExecutor is sufficient for subprocess-bound work.
  - Dynamic rate-limit adjustment based on failure type — that's v2.
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

from scope import Constraints, ScopeDecision
from tools import (
    ToolResult,
    TOOL_REGISTRY,
    run_subfinder,
    run_ffuf,
    run_gau,
    run_httpx,
    run_katana,
    run_getjs,
    run_linkfinder,
    run_gf,
    run_pattern_dedupe,
)


# ---------------------------------------------------------------------------
# ToolCall — structured representation of one model-proposed call
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    """A single tool invocation as proposed by the model (post-validation)."""
    tool: str
    args: dict
    scope_decision: Optional[ScopeDecision] = None
    # Populated after execution:
    result: Optional[ToolResult] = None


# ---------------------------------------------------------------------------
# Token-bucket rate limiter (per-tool)
# ---------------------------------------------------------------------------


class TokenBucket:
    """
    Thread-safe token-bucket rate limiter.

    Tokens replenish at `rate` tokens/second (= max_requests_per_min / 60).
    Each acquire() blocks until a token is available, then consumes one.
    """

    def __init__(self, max_requests_per_min: int) -> None:
        self._rate = max_requests_per_min / 60.0  # tokens per second
        self._capacity = float(max_requests_per_min)
        self._tokens = float(max_requests_per_min)  # start full
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        while True:
            with self._lock:
                now = time.monotonic()
                elapsed = now - self._last_refill
                self._tokens = min(
                    self._capacity,
                    self._tokens + elapsed * self._rate,
                )
                self._last_refill = now
                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return
                # Calculate how long until one token is available.
                wait = (1.0 - self._tokens) / self._rate
            time.sleep(wait)


# ---------------------------------------------------------------------------
# Executor
# ---------------------------------------------------------------------------


class Executor:
    """
    Manages the worker pool and per-tool rate limiters.

    Instantiate once per agent run and share across all batch turns.
    """

    def __init__(self, constraints: Constraints, outdir: Path) -> None:
        self._constraints = constraints
        self._outdir = outdir
        self._pool = ThreadPoolExecutor(
            max_workers=constraints.max_concurrent_calls,
            thread_name_prefix="recon_worker",
        )
        # Build one token bucket per tool we know about.
        self._buckets: dict[str, TokenBucket] = {}
        for tool in TOOL_REGISTRY:
            rpm = constraints.get_rate_limit(tool)
            self._buckets[tool] = TokenBucket(rpm)

    def _get_bucket(self, tool: str) -> TokenBucket:
        if tool not in self._buckets:
            # Unseen tool name — create a conservative default bucket.
            rpm = self._constraints.get_rate_limit(tool)
            self._buckets[tool] = TokenBucket(rpm)
        return self._buckets[tool]

    def _dispatch(self, call: ToolCall) -> ToolResult:
        """
        Called inside a worker thread: acquire rate-limit token, then invoke
        the appropriate tool wrapper.
        """
        bucket = self._get_bucket(call.tool)
        bucket.acquire()

        constraints = self._constraints
        outdir = self._outdir
        args = call.args

        # Dispatch by tool name.
        if call.tool == "subfinder":
            return run_subfinder(args["targets"], outdir, constraints)
        elif call.tool == "ffuf":
            return run_ffuf(args["target"], outdir, constraints,
                            wordlist=args.get("wordlist", "/usr/share/wordlists/dirb/common.txt"))
        elif call.tool == "gau":
            return run_gau(args["targets"], outdir, constraints)
        elif call.tool == "httpx":
            return run_httpx(args["targets"], outdir, constraints)
        elif call.tool == "katana":
            return run_katana(args["targets"], outdir, constraints)
        elif call.tool == "getJS":
            return run_getjs(args["targets"], outdir, constraints)
        elif call.tool == "linkfinder":
            return run_linkfinder(args["js_file_url"], outdir, constraints)
        elif call.tool == "gf":
            return run_gf(
                args["pattern"],
                Path(args["input_file"]),
                outdir,
                constraints,
            )
        elif call.tool == "pattern_dedupe":
            return run_pattern_dedupe(
                Path(args["input_file"]),
                Path(args["output_file"]),
                outdir,
                constraints,
                max_per_pattern=args.get("max_per_pattern", 1),
            )
        else:
            # Unknown tool — should have been caught by validation upstream,
            # but guard defensively.
            raise ValueError(f"Unknown tool: {call.tool!r}")

    def run_batch(self, calls: list[ToolCall]) -> Iterator[ToolCall]:
        """
        Submit all calls in *calls* to the worker pool and yield each
        ToolCall (with .result populated) as it completes.

        Results are yielded in completion order, NOT submission order —
        a fast call will yield before a slow one even if submitted later.
        agent.py should handle each result immediately (parse, write parsed/,
        discovery scope-check) without waiting for the rest of the batch.
        """
        if not calls:
            return

        future_to_call = {
            self._pool.submit(self._dispatch, call): call
            for call in calls
        }

        for future in as_completed(future_to_call):
            call = future_to_call[future]
            try:
                call.result = future.result()
            except Exception as exc:  # noqa: BLE001
                # The worker raised — synthesise a failed ToolResult so the
                # caller always gets a structured object back.
                call.result = ToolResult(
                    tool=call.tool,
                    target=str(call.args),
                    raw_path=self._outdir / "raw" / f"{call.tool}_error.txt",
                    exit_code=-1,
                    error_message=str(exc),
                )
                # Write the error to the raw file path for consistency.
                try:
                    call.result.raw_path.parent.mkdir(parents=True, exist_ok=True)
                    call.result.raw_path.write_text(
                        f"# EXECUTOR ERROR: {exc}\n", encoding="utf-8"
                    )
                except Exception:
                    pass

            yield call

    def shutdown(self, wait: bool = True) -> None:
        """Cleanly shut down the worker pool."""
        self._pool.shutdown(wait=wait)
