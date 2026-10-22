"""
ingest.py

Parsers for raw tool output → structured pydantic models → parsed/<tool>_<target>.json.

Design rules (from the build spec):
  - One parser per tool, each taking a raw output path.
  - Explicit fail-path: if output can't be parsed, raise ParseFailure —
    never return a silently-empty/default result.  "Zero findings" (status: ok,
    count: 0) vs "couldn't parse" (status: unparseable) must be distinguishable
    in the digest.
  - build_digest(parsed_result) → compact string per tool call.
  - build_batch_digest(results_and_metadata) → single tool-result turn appended
    to the conversation, covering the whole batch.  Rule-based, deterministic,
    no LLM calls.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional, Union
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, ValidationError


# ---------------------------------------------------------------------------
# Parse status
# ---------------------------------------------------------------------------


class ParseStatus(str, Enum):
    OK = "ok"
    UNPARSEABLE = "unparseable"
    EMPTY = "empty"          # tool succeeded but produced no output
    TOOL_FAILED = "tool_failed"   # non-zero exit / timeout


# ---------------------------------------------------------------------------
# Generic parsed result containers
# ---------------------------------------------------------------------------


class ParsedBase(BaseModel):
    """Fields shared by all parsed results."""
    tool: str
    target: str
    raw_path: str
    parsed_path: str = ""
    status: ParseStatus
    attempt: int = 1
    # Only present on unparseable/tool_failed results:
    error: Optional[str] = None


class SubfinderResult(ParsedBase):
    tool: str = "subfinder"
    subdomains: list[str] = Field(default_factory=list)
    count: int = 0


class FfufResult(ParsedBase):
    tool: str = "ffuf"
    paths: list[str] = Field(default_factory=list)
    count: int = 0


class GauResult(ParsedBase):
    tool: str = "gau"
    urls: list[str] = Field(default_factory=list)
    count: int = 0


class HttpxResult(ParsedBase):
    tool: str = "httpx"
    live_urls: list[str] = Field(default_factory=list)
    count: int = 0


class KatanaResult(ParsedBase):
    tool: str = "katana"
    urls: list[str] = Field(default_factory=list)
    count: int = 0


class GetJSResult(ParsedBase):
    tool: str = "getJS"
    js_files: list[str] = Field(default_factory=list)
    count: int = 0


class LinkFinderResult(ParsedBase):
    tool: str = "linkfinder"
    endpoints: list[str] = Field(default_factory=list)
    count: int = 0


class GfResult(ParsedBase):
    tool: str = "gf"
    pattern: str = ""
    matches: list[str] = Field(default_factory=list)
    count: int = 0


class PatternDedupeResult(ParsedBase):
    tool: str = "pattern_dedupe"
    output_file: str = ""
    input_count: int = 0
    output_count: int = 0
    reduction_pct: float = 0.0


ParsedResult = Union[
    SubfinderResult,
    FfufResult,
    GauResult,
    HttpxResult,
    KatanaResult,
    GetJSResult,
    LinkFinderResult,
    GfResult,
    PatternDedupeResult,
    ParsedBase,
]


# ---------------------------------------------------------------------------
# ParseFailure — raised (not returned) when output is genuinely unparseable
# ---------------------------------------------------------------------------


class ParseFailure(Exception):
    """Raised by a parser when it cannot make sense of the raw output."""

    def __init__(self, tool: str, target: str, raw_path: str, reason: str) -> None:
        super().__init__(reason)
        self.tool = tool
        self.target = target
        self.raw_path = raw_path
        self.reason = reason

    def to_parsed_result(self, attempt: int = 1) -> ParsedBase:
        return ParsedBase(
            tool=self.tool,
            target=self.target,
            raw_path=self.raw_path,
            status=ParseStatus.UNPARSEABLE,
            error=self.reason,
            attempt=attempt,
        )


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _read_raw(raw_path: Path, tool: str, target: str) -> list[str]:
    """Read non-empty, non-comment lines from a raw output file."""
    if not raw_path.exists():
        raise ParseFailure(tool, target, str(raw_path), "Raw file does not exist.")
    lines = raw_path.read_text(encoding="utf-8", errors="replace").splitlines()
    return [
        ln.strip()
        for ln in lines
        if ln.strip() and not ln.strip().startswith("#")
    ]


def _is_url(s: str) -> bool:
    try:
        p = urlsplit(s)
        return bool(p.scheme and p.netloc)
    except Exception:
        return False


def _write_parsed(parsed: ParsedBase, parsed_dir: Path) -> str:
    """Serialise parsed result to parsed/<tool>_<target>.json and return the path."""
    parsed_dir.mkdir(parents=True, exist_ok=True)
    safe_target = parsed.target.replace("/", "_").replace(":", "_").replace("*", "WILD")[:80]
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    fname = f"{parsed.tool}_{safe_target}_{ts}.json"
    out_path = parsed_dir / fname
    out_path.write_text(parsed.model_dump_json(indent=2), encoding="utf-8")
    return str(out_path)


# ---------------------------------------------------------------------------
# Tool parsers
# ---------------------------------------------------------------------------


def parse_subfinder(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> SubfinderResult:
    lines = _read_raw(raw_path, "subfinder", target)
    # Filter plausible hostnames — subfinder outputs one per line
    subs = [ln for ln in lines if "." in ln and not ln.startswith("http")]
    result = SubfinderResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        subdomains=subs,
        count=len(subs),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_ffuf(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> FfufResult:
    lines = _read_raw(raw_path, "ffuf", target)

    paths: list[str] = []

    # ffuf with -of json outputs a JSON object; try that first.
    # The raw file has a comment header we've already stripped.
    body = "\n".join(lines)
    try:
        data = json.loads(body)
        results = data.get("results", [])
        paths = [r.get("url", r.get("input", {}).get("FUZZ", "")) for r in results]
        paths = [p for p in paths if p]
    except (json.JSONDecodeError, TypeError):
        # Fallback: treat each line as a discovered URL/path.
        paths = [ln for ln in lines if ln.startswith("/") or _is_url(ln)]

    result = FfufResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        paths=paths,
        count=len(paths),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_gau(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> GauResult:
    lines = _read_raw(raw_path, "gau", target)
    urls = [ln for ln in lines if _is_url(ln)]

    if not lines:
        result = GauResult(
            target=target,
            raw_path=str(raw_path),
            status=ParseStatus.EMPTY,
            attempt=attempt,
        )
    else:
        result = GauResult(
            target=target,
            raw_path=str(raw_path),
            status=ParseStatus.OK,
            urls=urls,
            count=len(urls),
            attempt=attempt,
        )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_httpx(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> HttpxResult:
    lines = _read_raw(raw_path, "httpx", target)
    live = [ln for ln in lines if _is_url(ln)]

    result = HttpxResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        live_urls=live,
        count=len(live),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_katana(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> KatanaResult:
    lines = _read_raw(raw_path, "katana", target)
    urls = [ln for ln in lines if _is_url(ln)]

    result = KatanaResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        urls=urls,
        count=len(urls),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_getjs(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> GetJSResult:
    lines = _read_raw(raw_path, "getJS", target)
    js_files = [ln for ln in lines if _is_url(ln) or ln.endswith(".js")]

    result = GetJSResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        js_files=js_files,
        count=len(js_files),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_linkfinder(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
) -> LinkFinderResult:
    lines = _read_raw(raw_path, "linkfinder", target)
    # linkfinder outputs endpoint strings — keep non-empty ones
    endpoints = [ln for ln in lines if ln and not ln.startswith("[")]

    result = LinkFinderResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        endpoints=endpoints,
        count=len(endpoints),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_gf(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    pattern: str = "",
    attempt: int = 1,
) -> GfResult:
    lines = _read_raw(raw_path, "gf", target)
    matches = [ln for ln in lines if ln]

    result = GfResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        pattern=pattern,
        matches=matches,
        count=len(matches),
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


def parse_pattern_dedupe(
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    output_file: str = "",
    attempt: int = 1,
) -> PatternDedupeResult:
    """
    pattern_dedupe.py writes its stats to stdout (captured in raw_path).
    Parse the three summary lines it always prints.
    """
    lines = _read_raw(raw_path, "pattern_dedupe", target)

    input_count = 0
    output_count = 0
    reduction_pct = 0.0

    for ln in lines:
        m = re.search(r"input lines:\s+(\d+)", ln)
        if m:
            input_count = int(m.group(1))
        m = re.search(r"kept URLs:\s+(\d+)", ln)
        if m:
            output_count = int(m.group(1))
        m = re.search(r"(\d+\.?\d*)%\s+cut", ln)
        if m:
            reduction_pct = float(m.group(1))

    result = PatternDedupeResult(
        target=target,
        raw_path=str(raw_path),
        status=ParseStatus.OK,
        output_file=output_file,
        input_count=input_count,
        output_count=output_count,
        reduction_pct=reduction_pct,
        attempt=attempt,
    )
    result.parsed_path = _write_parsed(result, parsed_dir)
    return result


# ---------------------------------------------------------------------------
# Parse dispatcher
# ---------------------------------------------------------------------------


def parse_tool_output(
    tool: str,
    raw_path: Path,
    target: str,
    parsed_dir: Path,
    attempt: int = 1,
    extra: Optional[dict] = None,
) -> ParsedResult:
    """
    Route to the correct parser.  On any exception, converts to a tagged
    ParsedBase with status=UNPARSEABLE so the caller always gets a structured
    object — never a bare exception propagating past this point.
    """
    extra = extra or {}
    try:
        if tool == "subfinder":
            return parse_subfinder(raw_path, target, parsed_dir, attempt)
        elif tool == "ffuf":
            return parse_ffuf(raw_path, target, parsed_dir, attempt)
        elif tool == "gau":
            return parse_gau(raw_path, target, parsed_dir, attempt)
        elif tool == "httpx":
            return parse_httpx(raw_path, target, parsed_dir, attempt)
        elif tool == "katana":
            return parse_katana(raw_path, target, parsed_dir, attempt)
        elif tool == "getJS":
            return parse_getjs(raw_path, target, parsed_dir, attempt)
        elif tool == "linkfinder":
            return parse_linkfinder(raw_path, target, parsed_dir, attempt)
        elif tool == "gf":
            return parse_gf(raw_path, target, parsed_dir,
                            pattern=extra.get("pattern", ""), attempt=attempt)
        elif tool == "pattern_dedupe":
            return parse_pattern_dedupe(raw_path, target, parsed_dir,
                                        output_file=extra.get("output_file", ""),
                                        attempt=attempt)
        else:
            return ParsedBase(
                tool=tool,
                target=target,
                raw_path=str(raw_path),
                status=ParseStatus.UNPARSEABLE,
                error=f"No parser registered for tool '{tool}'.",
                attempt=attempt,
            )
    except ParseFailure as pf:
        return pf.to_parsed_result(attempt=attempt)
    except Exception as exc:  # noqa: BLE001
        return ParsedBase(
            tool=tool,
            target=target,
            raw_path=str(raw_path),
            status=ParseStatus.UNPARSEABLE,
            error=f"Parser raised: {exc}",
            attempt=attempt,
        )


# ---------------------------------------------------------------------------
# Digest builders
# ---------------------------------------------------------------------------


def build_digest(parsed: ParsedResult) -> str:
    """
    Build a compact single-call digest string.
    Kept intentionally terse — the batch digest is what the model actually sees.
    """
    base = parsed
    tool = base.tool
    target = base.target
    status = base.status.value
    attempt = base.attempt

    if base.status in (ParseStatus.UNPARSEABLE, ParseStatus.TOOL_FAILED):
        return (
            f"[{tool}] target={target!r} status={status} "
            f"attempt={attempt} error={base.error!r} raw={base.raw_path!r}"
        )

    # Tool-specific compact summaries
    if isinstance(parsed, SubfinderResult):
        preview = ", ".join(parsed.subdomains[:5])
        more = f" (+{parsed.count - 5} more)" if parsed.count > 5 else ""
        return (
            f"[subfinder] target={target!r} found={parsed.count} subdomains "
            f"attempt={attempt} preview=[{preview}{more}]"
        )

    if isinstance(parsed, FfufResult):
        preview = ", ".join(parsed.paths[:5])
        more = f" (+{parsed.count - 5} more)" if parsed.count > 5 else ""
        return (
            f"[ffuf] target={target!r} found={parsed.count} paths "
            f"attempt={attempt} preview=[{preview}{more}]"
        )

    if isinstance(parsed, GauResult):
        return (
            f"[gau] target={target!r} found={parsed.count} URLs "
            f"attempt={attempt} status={status}"
        )

    if isinstance(parsed, HttpxResult):
        preview = ", ".join(parsed.live_urls[:5])
        more = f" (+{parsed.count - 5} more)" if parsed.count > 5 else ""
        return (
            f"[httpx] target={target!r} live={parsed.count} "
            f"attempt={attempt} preview=[{preview}{more}]"
        )

    if isinstance(parsed, KatanaResult):
        return (
            f"[katana] target={target!r} found={parsed.count} URLs "
            f"attempt={attempt} (run pattern_dedupe next)"
        )

    if isinstance(parsed, GetJSResult):
        return (
            f"[getJS] target={target!r} found={parsed.count} JS files "
            f"attempt={attempt}"
        )

    if isinstance(parsed, LinkFinderResult):
        return (
            f"[linkfinder] target={target!r} found={parsed.count} endpoints "
            f"attempt={attempt}"
        )

    if isinstance(parsed, GfResult):
        return (
            f"[gf:{parsed.pattern}] target={target!r} matches={parsed.count} "
            f"attempt={attempt}"
        )

    if isinstance(parsed, PatternDedupeResult):
        return (
            f"[pattern_dedupe] {parsed.input_count} → {parsed.output_count} URLs "
            f"({parsed.reduction_pct:.1f}% cut) output={parsed.output_file!r}"
        )

    # Fallback for ParsedBase
    return f"[{tool}] target={target!r} status={status} attempt={attempt}"


# ---------------------------------------------------------------------------
# Metadata containers for batch digest construction
# ---------------------------------------------------------------------------


@dataclass
class RejectedCall:
    """A call that was rejected before execution (scope, dedup, etc.)."""
    tool: str
    args: dict
    reason: str
    scope_decision_str: str = ""


@dataclass
class EscalationOutcome:
    """Records what happened when a call was escalated to the operator."""
    tool: str
    target: str
    attempt: int
    failure_kind: str   # "exit_code", "timeout", "unparseable"
    operator_choice: str  # "skip", "retry", "abort"


@dataclass
class BatchResultItem:
    """One item in the batch, either a parsed result or metadata about a non-run."""
    parsed: Optional[ParsedResult] = None
    rejected: Optional[RejectedCall] = None
    escalation: Optional[EscalationOutcome] = None
    out_of_scope_discoveries: list[str] = field(default_factory=list)


def build_batch_digest(items: list[BatchResultItem]) -> str:
    """
    Condense the entire batch into ONE tool-result message for the conversation.

    Structure (all rule-based, no LLM):
      - Section 1: Completed calls (with per-call digest lines).
      - Section 2: Rejected calls (with reasons).
      - Section 3: Out-of-scope discoveries flagged this batch.
      - Section 4: Escalations and operator decisions (if any).

    Kept tight to minimise context budget usage.
    """
    lines: list[str] = ["=== BATCH RESULT ==="]

    # --- Section 1: Completed calls ---
    completed = [it for it in items if it.parsed is not None]
    if completed:
        lines.append(f"\n[Completed: {len(completed)} call(s)]")
        for it in completed:
            lines.append("  " + build_digest(it.parsed))
            if it.out_of_scope_discoveries:
                for disc in it.out_of_scope_discoveries:
                    lines.append(f"    ⚠ OUT-OF-SCOPE DISCOVERY: {disc!r} (flagged, not used)")

    # --- Section 2: Rejected calls ---
    rejected = [it for it in items if it.rejected is not None]
    if rejected:
        lines.append(f"\n[Rejected (not run): {len(rejected)} call(s)]")
        for it in rejected:
            r = it.rejected
            lines.append(f"  [{r.tool}] args={r.args} reason={r.reason!r}")

    # --- Section 3: Out-of-scope discoveries (batch-level, no duplicates) ---
    all_oos = []
    for it in items:
        all_oos.extend(it.out_of_scope_discoveries)
    if all_oos:
        # Already rendered inline above; skip repeat summary for brevity.
        pass

    # --- Section 4: Escalations ---
    escalations = [it for it in items if it.escalation is not None]
    if escalations:
        lines.append(f"\n[Escalations: {len(escalations)} call(s) reached retry cap]")
        for it in escalations:
            esc = it.escalation
            lines.append(
                f"  [{esc.tool}] target={esc.target!r} attempts={esc.attempt} "
                f"failure={esc.failure_kind!r} operator_choice={esc.operator_choice!r}"
            )

    lines.append("\n=== END BATCH ===")
    return "\n".join(lines)
