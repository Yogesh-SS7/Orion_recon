"""
agent.py — Entrypoint for the Recon Orchestration Agent.

Usage:
    python3 agent.py scope.json [options]

Options:
    --outdir DIR            Output directory (default: scope-hash-derived folder)
    --max-iterations N      Max model turns before forced exit (default: 30)
    --resume OUTDIR         Resume a previous run from its agent.log
    --model MODEL           Ollama model to use (default: qwen2.5:7b)
    --num-ctx N             Context window size passed to Ollama (default: 8192)
                            IMPORTANT: Ollama defaults to 2048, silently truncating
                            history. Set this explicitly to avoid mid-run "forgetting".
    --max-batch-size N      Max tool calls accepted from one model turn (default: 4).
                            A 7B model reasoning correctly about 2-4 calls is safer
                            than trusting it with 10+ at once.

Architecture note: this file implements the outer agent loop only.  Heavy
lifting is split across:
    scope.py    — Scope model + ScopeChecker
    tools.py    — One wrapper per CLI tool + Ollama tool schemas
    executor.py — ThreadPoolExecutor + per-tool token-bucket rate limiting
    ingest.py   — Parsers, digest builders (per-call and batch-level)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Optional

import ollama
from pydantic import BaseModel, ValidationError

from scope import Scope, ScopeChecker, load_scope, scope_output_dir, Decision
from tools import TOOL_SCHEMAS, ToolResult
from executor import Executor, ToolCall
from ingest import (
    parse_tool_output,
    build_batch_digest,
    BatchResultItem,
    RejectedCall,
    EscalationOutcome,
    ParseStatus,
)


# ---------------------------------------------------------------------------
# Config constants
# ---------------------------------------------------------------------------

DEFAULT_MODEL = "qwen2.5:7b"

# WHY 8192: Ollama's default num_ctx is 2048 — far too small for a multi-turn
# agentic loop with batch digests.  Qwen2.5:7B supports up to 32K natively,
# but 8192 is a safe ceiling that fits comfortably on most consumer GPUs and
# keeps per-turn digest cost manageable.  Override with --num-ctx if hardware
# allows more.
DEFAULT_NUM_CTX = 8192

DEFAULT_MAX_ITERATIONS = 30
DEFAULT_MAX_BATCH_SIZE = 4   # 7B models handle 2-4 concurrent calls reliably


# ---------------------------------------------------------------------------
# Call state tracking (per session, persisted in agent.log for --resume)
# ---------------------------------------------------------------------------


class CallState(str, Enum):
    NEVER_RUN = "NEVER_RUN"
    SUCCEEDED = "SUCCEEDED"
    FAILED_BELOW_CAP = "FAILED_BELOW_CAP"
    ESCALATED = "ESCALATED"


@dataclass
class CallStateEntry:
    state: CallState = CallState.NEVER_RUN
    failure_count: int = 0
    operator_choice: Optional[str] = None   # "skip" | "retry" | "abort"


def _call_key(tool: str, target: str) -> str:
    """Stable key for (tool, normalised-target) lookup."""
    return f"{tool}::{target.strip().lower()}"


# ---------------------------------------------------------------------------
# Pydantic model for validating raw Ollama tool_call args
# ---------------------------------------------------------------------------


class ToolCallArgs(BaseModel):
    """
    Minimal validation wrapper — the real per-tool validation happens when
    the dispatcher checks required fields by tool name.
    We catch missing / wrong-type required fields here before they reach executor.
    """
    model_config = {"extra": "allow"}


REQUIRED_ARGS: dict[str, list[str]] = {
    "subfinder": ["targets"],
    "ffuf": ["target"],
    "gau": ["targets"],
    "httpx": ["targets"],
    "katana": ["targets"],
    "getJS": ["targets"],
    "linkfinder": ["js_file_url"],
    "gf": ["pattern", "input_file"],
    "pattern_dedupe": ["input_file", "output_file"],
}

VALID_TOOL_NAMES = set(REQUIRED_ARGS.keys())


def validate_tool_call(name: str, args: dict) -> Optional[str]:
    """
    Return an error string if the call is invalid, None if it passes.
    Called before scope-checking so malformed calls never reach the executor.
    """
    if name not in VALID_TOOL_NAMES:
        return f"Unknown tool '{name}'. Valid tools: {sorted(VALID_TOOL_NAMES)}"
    for req in REQUIRED_ARGS.get(name, []):
        if req not in args:
            return f"Tool '{name}' missing required arg '{req}'."
        val = args[req]
        if val is None or val == "" or val == []:
            return f"Tool '{name}' arg '{req}' is empty."
    return None


# ---------------------------------------------------------------------------
# agent.log helpers
# ---------------------------------------------------------------------------


def append_log(log_path: Path, obj: dict) -> None:
    """Append one JSON object (one line) to agent.log, then flush."""
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(obj, default=str) + "\n")
        fh.flush()


def load_log(log_path: Path) -> list[dict]:
    """Read all JSON lines from agent.log; skip malformed lines."""
    if not log_path.exists():
        return []
    records = []
    for ln in log_path.read_text(encoding="utf-8").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            records.append(json.loads(ln))
        except json.JSONDecodeError:
            pass
    return records


# ---------------------------------------------------------------------------
# System prompt
# ---------------------------------------------------------------------------


def build_system_prompt(scope: Scope, outdir: Path) -> str:
    """
    Describe the agent's mission, available tools, scope summary, and
    output conventions.
    """
    in_scope_str = ", ".join(scope.in_scope)
    out_scope_str = ", ".join(scope.out_of_scope) if scope.out_of_scope else "none"

    return f"""You are an autonomous recon agent conducting authorized bug-bounty / penetration-testing reconnaissance.

## MISSION
Follow the recon pipeline to produce a ranked, explained candidate list of potentially vulnerable parameters — NOT a raw pass-through of tool output.

Pipeline order (adapt based on results, but generally follow this sequence):
1. subfinder  → discover subdomains
2. gau        → fetch historical URLs for discovered subdomains
3. httpx      → confirm which hosts are live
4. ffuf       → directory/content discovery on live hosts
5. katana     → active crawl on live URLs (parameter mining)
6. pattern_dedupe → collapse katana output (tens of thousands → hundreds)
7. getJS      → extract JS file URLs from live pages
8. linkfinder → parse each JS file for embedded endpoints
9. pattern_dedupe → collapse merged katana+linkfinder output
10. gf [xss, ssrf, sqli, idor, lfi, redirect, rce] → per-vuln-class shortlists
11. FINAL ANSWER → ranked candidate list with per-candidate reasoning

## SCOPE
In scope:  {in_scope_str}
Out of scope: {out_scope_str}
Output directory: {outdir}

## TOOL CALL RULES
- You may propose MULTIPLE tool calls in one turn (a batch). Keep batches small (2–4 calls) for reliability.
- Do NOT propose the same (tool, target) pair twice if it already succeeded.
- Do NOT specify rate, threads, delay, concurrency, wordlist, or crawl-depth parameters — those are fixed by scope.json. Only specify WHAT to run and on WHAT target.
- If a call fails, you may retry it in a later turn (up to the configured cap). After that, an operator will decide.
- When you have gathered enough information, stop calling tools and produce your FINAL ANSWER.

## FINAL ANSWER FORMAT
When ready to conclude, respond with plain text (no tool calls) containing:
1. A ranked candidate list — each entry: URL, matched vuln class(es), why it's a candidate, false-positive considerations.
2. A section: "Out-of-scope discoveries flagged during run" (list from agent digests).
3. A section: "Escalated calls and operator decisions" (from agent digests).

Do not re-emit raw tool output. Reason about what was found.
"""


# ---------------------------------------------------------------------------
# Human escalation
# ---------------------------------------------------------------------------


def prompt_operator_escalation(
    tool: str,
    target: str,
    attempt: int,
    failure_kind: str,
    raw_path: str,
) -> str:
    """
    Block on stdin and ask the operator what to do about a call that hit the
    retry cap.  Returns "skip", "retry", or "abort".

    v1: plain input() — no TUI needed.  operator is expected to be present.
    """
    print("\n" + "=" * 60)
    print("⚠  ESCALATION: Tool call has hit the retry cap.")
    print(f"   Tool:    {tool}")
    print(f"   Target:  {target}")
    print(f"   Attempt: {attempt}")
    print(f"   Failure: {failure_kind}")
    print(f"   Raw output: {raw_path}")
    print("=" * 60)
    print("Options:")
    print("  skip   — mark permanently failed, continue the run")
    print("  retry  — reset count to 0, allow the model to try again")
    print("  abort  — stop immediately and write summary.md")
    print()

    while True:
        choice = input("Your choice [skip/retry/abort]: ").strip().lower()
        if choice in ("skip", "retry", "abort"):
            return choice
        print(f"  Invalid choice '{choice}'. Please enter skip, retry, or abort.")


# ---------------------------------------------------------------------------
# summary.md writer
# ---------------------------------------------------------------------------


def write_summary(
    outdir: Path,
    conversation: list[dict],
    final_answer: Optional[str],
    call_states: dict[str, CallStateEntry],
    oos_discoveries: list[str],
    escalation_log: list[dict],
    turn: int,
) -> None:
    summary_path = outdir / "summary.md"

    lines = [
        "# Recon Agent — Run Summary",
        "",
        f"**Completed at:** {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"**Turns completed:** {turn}",
        f"**Output directory:** `{outdir}`",
        "",
    ]

    if final_answer:
        lines += ["## Final Answer", "", final_answer, ""]
    else:
        lines += [
            "## Final Answer",
            "",
            "_Run ended without a final answer (max iterations reached or aborted)._",
            "",
        ]

    # Out-of-scope discoveries
    lines += ["## Out-of-Scope Discoveries Flagged", ""]
    if oos_discoveries:
        for d in sorted(set(oos_discoveries)):
            lines.append(f"- {d}")
    else:
        lines.append("_None._")
    lines.append("")

    # Escalation log
    lines += ["## Escalated Calls and Operator Decisions", ""]
    if escalation_log:
        for e in escalation_log:
            lines.append(
                f"- **{e['tool']}** target=`{e['target']}` "
                f"attempt={e['attempt']} failure=`{e['failure_kind']}` "
                f"→ operator chose **{e['operator_choice']}**"
            )
    else:
        lines.append("_None._")
    lines.append("")

    # Call state summary
    lines += ["## Call State Summary", ""]
    for key, entry in sorted(call_states.items()):
        lines.append(
            f"- `{key}`: {entry.state.value}"
            + (f" (op: {entry.operator_choice})" if entry.operator_choice else "")
        )
    lines.append("")

    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\n[agent] Summary written to {summary_path}")


# ---------------------------------------------------------------------------
# Core agent loop
# ---------------------------------------------------------------------------


def run_agent(
    scope_path: Path,
    outdir: Optional[Path],
    max_iterations: int,
    resume_dir: Optional[Path],
    model: str,
    num_ctx: int,
    max_batch_size: int,
) -> None:
    # --- Load scope ---
    scope = load_scope(scope_path)
    checker = ScopeChecker(scope)

    # --- Resolve output directory ---
    if outdir is None:
        outdir = scope_output_dir(scope_path)
    outdir.mkdir(parents=True, exist_ok=True)
    (outdir / "raw").mkdir(exist_ok=True)
    (outdir / "parsed").mkdir(exist_ok=True)
    log_path = outdir / "agent.log"

    print(f"[agent] Output directory: {outdir}")
    print(f"[agent] Model: {model}  num_ctx: {num_ctx}  max_batch_size: {max_batch_size}")

    # Write a startup entry immediately — before the first model call — so that
    # agent.log always exists even if the run crashes on turn 1.
    append_log(log_path, {
        "event": "startup",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "model": model,
        "num_ctx": num_ctx,
        "max_batch_size": max_batch_size,
        "scope_path": str(scope_path),
        "outdir": str(outdir),
        "in_scope": scope.in_scope,
        "out_of_scope": scope.out_of_scope,
    })

    # --- Executor (owns pool + rate limiters for the whole run) ---
    executor = Executor(scope.constraints, outdir)

    # --- Session state ---
    call_states: dict[str, CallStateEntry] = {}
    oos_discoveries: list[str] = []
    escalation_log: list[dict] = []
    conversation: list[dict] = []
    turn = 0
    final_answer: Optional[str] = None

    # --- Resume or start fresh ---
    if resume_dir is not None:
        resume_log = resume_dir / "agent.log"
        if not resume_log.exists():
            print(f"[agent] ERROR: No agent.log found in {resume_dir}", file=sys.stderr)
            sys.exit(1)
        print(f"[agent] Resuming from {resume_log}")
        records = load_log(resume_log)
        for rec in records:
            # Reconstruct conversation
            if "model_message" in rec:
                conversation.append({"role": "assistant", "content": rec["model_message"]})
            if "batch_digest" in rec:
                conversation.append({"role": "tool", "content": rec["batch_digest"]})
            # Reconstruct call states
            for tc in rec.get("tool_calls", []):
                key = _call_key(tc.get("tool", ""), tc.get("args", {}).get("target", str(tc.get("args", {}))))
                status = tc.get("status", "")
                attempt = tc.get("attempt", 1)
                escalated = tc.get("escalated", False)
                op_choice = tc.get("operator_choice")
                if status == "ok":
                    call_states[key] = CallStateEntry(state=CallState.SUCCEEDED, failure_count=0)
                elif escalated:
                    call_states[key] = CallStateEntry(
                        state=CallState.ESCALATED,
                        failure_count=attempt,
                        operator_choice=op_choice,
                    )
                elif status == "failed":
                    call_states[key] = CallStateEntry(
                        state=CallState.FAILED_BELOW_CAP,
                        failure_count=attempt,
                    )
            turn = rec.get("turn", turn) + 1
        print(f"[agent] Replayed {len(records)} turns, resuming at turn {turn}")
    else:
        # Fresh start — seed the conversation with a user message
        conversation = [
            {"role": "system", "content": build_system_prompt(scope, outdir)},
            {
                "role": "user",
                "content": (
                    f"Begin the recon pipeline for the following scope:\n\n"
                    f"In scope: {', '.join(scope.in_scope)}\n"
                    f"Out of scope: {', '.join(scope.out_of_scope) if scope.out_of_scope else 'none'}\n\n"
                    f"Propose your first batch of tool calls."
                ),
            },
        ]

    # --- Main loop ---
    try:
        while turn < max_iterations:
            print(f"\n[agent] === Turn {turn + 1} / {max_iterations} ===")

            # 1. Call the model
            try:
                response = ollama.chat(
                    model=model,
                    messages=conversation,
                    tools=TOOL_SCHEMAS,
                    options={"num_ctx": num_ctx},
                )
            except Exception as exc:
                print(f"[agent] ERROR: Ollama call failed: {exc}", file=sys.stderr)
                print("[agent] Waiting 5s before retry...")
                time.sleep(5)
                continue

            # Parse the response — ollama returns a ChatResponse object (attribute
            # access), NOT a plain dict.  Using .get() on it raises AttributeError
            # and kills the run before agent.log is ever written.
            try:
                msg = response.message
                model_text = (msg.content or "").strip() if msg.content is not None else ""
                raw_tool_calls = msg.tool_calls or []
            except AttributeError:
                # Fallback: some ollama versions return a plain dict.
                try:
                    msg = response.get("message", {})
                    model_text = (msg.get("content", "") or "").strip()
                    raw_tool_calls = msg.get("tool_calls") or []
                except Exception as exc:
                    print(f"[agent] ERROR: Could not parse Ollama response: {exc}", file=sys.stderr)
                    print(f"[agent]   Raw response type: {type(response)}, value: {response!r}", file=sys.stderr)
                    print("[agent] Waiting 5s before retry...")
                    time.sleep(5)
                    continue

            # 2. Check for final answer (no tool calls = model is done)
            if not raw_tool_calls:
                # Guard: don't accept a "final answer" if no tools have run yet.
                # A 7B model sometimes produces a text reply on turn 1 instead of
                # proposing tool calls — that would leave raw/ and parsed/ empty.
                tools_have_run = any(
                    e.state == CallState.SUCCEEDED
                    for e in call_states.values()
                )
                if model_text.strip() and tools_have_run:
                    print("[agent] Model produced final answer.")
                    final_answer = model_text
                    conversation.append({"role": "assistant", "content": model_text})
                    break
                elif model_text.strip() and not tools_have_run:
                    print(
                        "[agent] WARNING: Model tried to give a final answer before "
                        "running any tools. Nudging it to start the pipeline."
                    )
                    conversation.append({"role": "assistant", "content": model_text})
                    conversation.append({
                        "role": "user",
                        "content": (
                            "You haven't run any recon tools yet. Do NOT provide a "
                            "final answer until you have completed the pipeline steps. "
                            "Start with subfinder and gau on the in-scope targets now."
                        ),
                    })
                    turn += 1
                    continue
                else:
                    # Empty response — nudge the model
                    print("[agent] Empty model response. Nudging...")
                    conversation.append({
                        "role": "user",
                        "content": (
                            "You sent an empty response. Either propose tool calls "
                            "for the next recon step, or provide your final ranked "
                            "candidate list if the recon is complete."
                        ),
                    })
                    turn += 1
                    continue

            # 3. Cap batch size (7B reliability guard)
            if len(raw_tool_calls) > max_batch_size:
                print(
                    f"[agent] Model proposed {len(raw_tool_calls)} calls; "
                    f"capping at {max_batch_size}."
                )
                raw_tool_calls = raw_tool_calls[:max_batch_size]

            conversation.append({"role": "assistant", "content": model_text, "tool_calls": raw_tool_calls})

            # 4. Validate + gating pass (sequential, cheap, before executor)
            approved_calls: list[ToolCall] = []
            batch_items: list[BatchResultItem] = []
            log_tool_calls: list[dict] = []

            for raw_call in raw_tool_calls:
                # Ollama returns ToolCall objects with attribute access (.function.name,
                # .function.arguments) — NOT dicts.  Some older versions return dicts.
                # Handle both without crashing.
                try:
                    fn = raw_call.function
                    tool_name = fn.name or ""
                    raw_args = fn.arguments or {}
                except AttributeError:
                    # Fallback: dict-style (older ollama or mocked in tests)
                    tool_name = raw_call.get("function", {}).get("name", "")
                    raw_args = raw_call.get("function", {}).get("arguments", {})

                # Ollama sometimes stringifies args even in object mode
                if isinstance(raw_args, str):
                    try:
                        raw_args = json.loads(raw_args)
                    except json.JSONDecodeError:
                        raw_args = {}

                # 4a. Pydantic / schema validation
                validation_err = validate_tool_call(tool_name, raw_args)
                if validation_err:
                    print(f"[agent] REJECTED (validation): {tool_name} — {validation_err}")
                    batch_items.append(BatchResultItem(
                        rejected=RejectedCall(
                            tool=tool_name,
                            args=raw_args,
                            reason=f"Validation error: {validation_err}",
                        )
                    ))
                    log_tool_calls.append({
                        "tool": tool_name,
                        "args": raw_args,
                        "scope_decision": "rejected",
                        "reason": f"Validation error: {validation_err}",
                        "status": "not_run",
                    })
                    continue

                # 4b. Determine the primary target for scope checking + call-state lookup
                target_for_scope = _primary_target(tool_name, raw_args)
                key = _call_key(tool_name, target_for_scope)

                # 4c. Call-state check
                entry = call_states.get(key, CallStateEntry())
                if entry.state == CallState.SUCCEEDED:
                    # Point the model at the existing parsed file instead of re-running.
                    reason = f"Already succeeded this session. Use existing parsed output."
                    print(f"[agent] REJECTED (already done): {tool_name} {target_for_scope!r}")
                    batch_items.append(BatchResultItem(
                        rejected=RejectedCall(tool=tool_name, args=raw_args, reason=reason)
                    ))
                    log_tool_calls.append({
                        "tool": tool_name,
                        "args": raw_args,
                        "scope_decision": "rejected",
                        "reason": reason,
                        "status": "not_run",
                    })
                    continue

                if entry.state == CallState.ESCALATED and entry.operator_choice != "retry":
                    reason = "Already escalated this session; operator did not choose retry."
                    print(f"[agent] REJECTED (escalated): {tool_name} {target_for_scope!r}")
                    batch_items.append(BatchResultItem(
                        rejected=RejectedCall(tool=tool_name, args=raw_args, reason=reason)
                    ))
                    log_tool_calls.append({
                        "tool": tool_name,
                        "args": raw_args,
                        "scope_decision": "rejected",
                        "reason": reason,
                        "status": "not_run",
                    })
                    continue

                # 4d. Scope check on the primary target
                decision = checker.check_input(target_for_scope)
                if decision.decision != Decision.ALLOWED:
                    reason = decision.reason
                    print(f"[agent] REJECTED (out-of-scope): {tool_name} {target_for_scope!r} — {reason}")
                    batch_items.append(BatchResultItem(
                        rejected=RejectedCall(
                            tool=tool_name,
                            args=raw_args,
                            reason=f"Scope rejection: {reason}",
                            scope_decision_str=decision.decision.value,
                        )
                    ))
                    log_tool_calls.append({
                        "tool": tool_name,
                        "args": raw_args,
                        "scope_decision": decision.decision.value,
                        "reason": reason,
                        "status": "not_run",
                    })
                    continue

                # Passed all gates — add to approved batch
                tc = ToolCall(tool=tool_name, args=raw_args, scope_decision=decision)
                approved_calls.append(tc)
                print(f"[agent] APPROVED: {tool_name} target={target_for_scope!r}")

            # 5. Concurrent execution pass
            for completed_call in executor.run_batch(approved_calls):
                result: ToolResult = completed_call.result
                tool_name = completed_call.tool
                target_for_scope = _primary_target(tool_name, completed_call.args)
                key = _call_key(tool_name, target_for_scope)
                entry = call_states.get(key, CallStateEntry())
                attempt = entry.failure_count + 1

                # Determine failure kind
                if result.timed_out:
                    failure_kind = "timeout"
                elif result.exit_code != 0:
                    failure_kind = f"exit_code={result.exit_code}"
                else:
                    failure_kind = None

                # Parse raw output (even on failure — get what we can)
                extra = {}
                if tool_name == "gf":
                    extra["pattern"] = completed_call.args.get("pattern", "")
                elif tool_name == "pattern_dedupe":
                    extra["output_file"] = completed_call.args.get("output_file", "")

                parsed = parse_tool_output(
                    tool=tool_name,
                    raw_path=result.raw_path,
                    target=target_for_scope,
                    parsed_dir=outdir / "parsed",
                    attempt=attempt,
                    extra=extra,
                )

                # Check if parse itself failed even though tool exited 0
                if parsed.status == ParseStatus.UNPARSEABLE and failure_kind is None:
                    failure_kind = "unparseable"

                # Update call state
                if failure_kind is not None:
                    entry.failure_count += 1
                    if entry.failure_count >= scope.constraints.max_retries_per_call:
                        entry.state = CallState.ESCALATED  # escalation pending
                    else:
                        entry.state = CallState.FAILED_BELOW_CAP
                    call_states[key] = entry
                else:
                    entry.state = CallState.SUCCEEDED
                    call_states[key] = entry

                # Discovery scope-check on newly found hosts/URLs
                discovered_oos: list[str] = []
                all_discovered = _extract_discoveries(tool_name, parsed)
                if all_discovered:
                    decisions = checker.check_discovery(all_discovered)
                    for d in decisions:
                        if d.decision != Decision.ALLOWED:
                            discovered_oos.append(d.target)
                            oos_discoveries.append(d.target)
                            print(f"[agent] OUT-OF-SCOPE DISCOVERY: {d.target!r} ({d.reason})")

                batch_items.append(BatchResultItem(
                    parsed=parsed,
                    out_of_scope_discoveries=discovered_oos,
                ))
                log_tool_calls.append({
                    "tool": tool_name,
                    "args": completed_call.args,
                    "scope_decision": "allowed",
                    "raw_path": str(result.raw_path),
                    "parsed_path": parsed.parsed_path if hasattr(parsed, "parsed_path") else "",
                    "discoveries_flagged": discovered_oos,
                    "status": "ok" if failure_kind is None else "failed",
                    "attempt": attempt,
                    "failure_kind": failure_kind,
                })

            # 6. Human escalation — AFTER batch settles, never mid-run
            for i, (call, log_entry) in enumerate(
                zip(approved_calls, [lc for lc in log_tool_calls if lc.get("scope_decision") == "allowed"])
            ):
                key = _call_key(call.tool, _primary_target(call.tool, call.args))
                entry = call_states.get(key, CallStateEntry())
                if entry.state != CallState.ESCALATED or entry.operator_choice is not None:
                    continue
                # This call just hit the cap and hasn't been prompted yet.
                failure_kind = log_entry.get("failure_kind", "unknown")
                raw_path = log_entry.get("raw_path", "")
                attempt = log_entry.get("attempt", 1)
                target_display = _primary_target(call.tool, call.args)

                choice = prompt_operator_escalation(
                    call.tool, target_display, attempt, failure_kind, raw_path
                )
                entry.operator_choice = choice
                call_states[key] = entry

                esc = EscalationOutcome(
                    tool=call.tool,
                    target=target_display,
                    attempt=attempt,
                    failure_kind=failure_kind,
                    operator_choice=choice,
                )
                escalation_log.append(asdict(esc))
                # Find corresponding BatchResultItem and attach escalation
                for bi in batch_items:
                    if bi.parsed and bi.parsed.tool == call.tool and bi.parsed.target == target_display:
                        bi.escalation = esc
                        break

                log_entry["escalated"] = True
                log_entry["operator_choice"] = choice

                if choice == "abort":
                    print("[agent] Operator chose ABORT. Writing summary and exiting.")
                    batch_digest = build_batch_digest(batch_items)
                    append_log(log_path, {
                        "turn": turn + 1,
                        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "model_message": model_text,
                        "tool_calls": log_tool_calls,
                        "batch_digest": batch_digest,
                    })
                    write_summary(
                        outdir, conversation, None,
                        call_states, oos_discoveries, escalation_log, turn + 1
                    )
                    executor.shutdown(wait=False)
                    sys.exit(0)

                if choice == "retry":
                    # Reset failure count so model can try again next turn.
                    entry.state = CallState.FAILED_BELOW_CAP
                    entry.failure_count = 0
                    entry.operator_choice = None
                    call_states[key] = entry

            # 7. Build batch digest and append to conversation
            batch_digest = build_batch_digest(batch_items)
            print(f"\n[agent] Batch digest:\n{batch_digest}")

            conversation.append({"role": "tool", "content": batch_digest})

            # 8. Append batch turn to agent.log (flush immediately)
            append_log(log_path, {
                "turn": turn + 1,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "model_message": model_text,
                "tool_calls": log_tool_calls,
                "batch_digest": batch_digest,
            })

            turn += 1

    except KeyboardInterrupt:
        print("\n[agent] Interrupted by user. Writing summary...")
    finally:
        executor.shutdown(wait=True)

    # Write final summary
    write_summary(
        outdir, conversation, final_answer,
        call_states, oos_discoveries, escalation_log, turn
    )


# ---------------------------------------------------------------------------
# Helpers for extracting primary target and discoveries from parsed results
# ---------------------------------------------------------------------------


def _primary_target(tool: str, args: dict) -> str:
    """Extract the primary target string for call-state keying and scope checks."""
    if tool in ("subfinder", "gau", "httpx", "katana", "getJS"):
        targets = args.get("targets", [])
        return ",".join(targets) if targets else str(args)
    elif tool == "ffuf":
        return args.get("target", str(args))
    elif tool == "linkfinder":
        return args.get("js_file_url", str(args))
    elif tool == "gf":
        return args.get("pattern", str(args))
    elif tool == "pattern_dedupe":
        return args.get("input_file", str(args))
    return str(args)


def _extract_discoveries(tool: str, parsed) -> list[str]:
    """
    Return any hosts/URLs newly discovered by this tool call that should be
    scope-checked.  Only return items not already in the original target set.
    """
    from ingest import SubfinderResult, HttpxResult, KatanaResult, GauResult, GetJSResult, LinkFinderResult

    if isinstance(parsed, SubfinderResult):
        return parsed.subdomains
    if isinstance(parsed, HttpxResult):
        return parsed.live_urls
    if isinstance(parsed, KatanaResult):
        return parsed.urls
    if isinstance(parsed, GauResult):
        return parsed.urls
    if isinstance(parsed, GetJSResult):
        return parsed.js_files
    if isinstance(parsed, LinkFinderResult):
        return parsed.endpoints
    return []


# ---------------------------------------------------------------------------
# CLI entrypoint
# ---------------------------------------------------------------------------


def _build_scope_from_target(target: str, exclude: list[str]) -> dict:
    """
    Auto-generate a minimal scope dict from a bare domain string.
    Automatically includes the root domain AND *.root wildcard.
    """
    # Strip any scheme the user may have typed (https://evil.com -> evil.com)
    domain = target.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")

    return {
        "in_scope": [domain, f"*.{domain}"],
        "out_of_scope": [e.strip() for e in exclude if e.strip()],
        "constraints": {
            "max_concurrent_calls": 4,
            "max_retries_per_call": 2,
            "request_delay_ms": 0,
            "crawl_depth": 2,
            "tool_timeout_seconds": {"katana": 1800, "ffuf": 900},
            "rate_limits": {
                "subfinder": {"max_requests_per_min": 60},
                "gau":       {"max_requests_per_min": 60},
                "httpx":     {"max_requests_per_min": 30},
                "ffuf":      {"max_requests_per_min": 15},
                "katana":    {"max_requests_per_min": 15},
            },
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Recon Orchestration Agent — LLM-driven, scope-enforced recon pipeline.\n\n"
            "Quick start (no JSON needed):\n"
            "  python3 agent.py --target evil.com\n\n"
            "Full control:\n"
            "  python3 agent.py scope.json\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # --- Input: either a scope.json path OR --target domain ---
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "scope",
        type=Path,
        nargs="?",
        default=None,
        help="Path to a scope.json file (full control over all settings).",
    )
    input_group.add_argument(
        "--target", "-t",
        metavar="DOMAIN",
        default=None,
        help=(
            "Target domain to recon (e.g. evil.com). "
            "Automatically scopes root domain + *.root with sane defaults. "
            "Saves an auto-generated scope.json into the output folder."
        ),
    )

    parser.add_argument(
        "--exclude", "-x",
        metavar="DOMAIN",
        nargs="+",
        default=[],
        help="Domains to exclude from scope (only valid with --target). E.g. --exclude staging.evil.com",
    )
    parser.add_argument(
        "--outdir", type=Path, default=None,
        help="Output directory (default: auto-derived from scope content hash).",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=DEFAULT_MAX_ITERATIONS,
        help=f"Maximum model turns before forced exit (default: {DEFAULT_MAX_ITERATIONS}).",
    )
    parser.add_argument(
        "--resume", type=Path, default=None, metavar="OUTDIR",
        help="Resume a previous run from its output directory (reads agent.log).",
    )
    parser.add_argument(
        "--model", default=DEFAULT_MODEL,
        help=f"Ollama model name (default: {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--num-ctx", type=int, default=DEFAULT_NUM_CTX, dest="num_ctx",
        help=(
            f"Ollama context window size (default: {DEFAULT_NUM_CTX}). "
            "Ollama defaults to 2048, which silently truncates history mid-run. "
            "Raise this if hardware allows."
        ),
    )
    parser.add_argument(
        "--max-batch-size", type=int, default=DEFAULT_MAX_BATCH_SIZE, dest="max_batch_size",
        help=(
            f"Max tool calls accepted from one model turn (default: {DEFAULT_MAX_BATCH_SIZE}). "
            "7B models handle 2-4 simultaneous calls reliably."
        ),
    )

    args = parser.parse_args()

    # Guard: --exclude only makes sense with --target
    if args.exclude and args.target is None:
        parser.error("--exclude can only be used with --target")

    # -------------------------------------------------------------------------
    # Resolve scope: either load from file or auto-generate from --target
    # -------------------------------------------------------------------------
    if args.target:
        scope_dict = _build_scope_from_target(args.target, args.exclude)

        # Validate the generated scope through pydantic before anything else.
        try:
            scope = Scope.model_validate(scope_dict)
        except ValidationError as exc:
            print(f"ERROR: Auto-generated scope failed validation: {exc}", file=sys.stderr)
            sys.exit(1)

        # Determine output directory early so we can save scope.json inside it.
        from scope import scope_output_dir as _sod
        import tempfile, hashlib

        # We need a stable path for scope.json — derive the outdir from the
        # scope dict content (same logic as scope_output_dir, inline here
        # since we don't have a file yet).
        canonical = json.dumps(scope_dict, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]
        outdir = args.outdir if args.outdir else Path(f"recon_{digest}")
        outdir.mkdir(parents=True, exist_ok=True)

        # Write scope.json into the output folder for reproducibility + --resume.
        scope_path = outdir / "scope.json"
        if not scope_path.exists():
            scope_path.write_text(
                json.dumps(scope_dict, indent=2), encoding="utf-8"
            )
            print(f"[agent] Auto-generated scope.json saved to {scope_path}")
        else:
            print(f"[agent] Reusing existing scope.json at {scope_path}")

        print(f"[agent] Target: {args.target}")
        if args.exclude:
            print(f"[agent] Excluded: {', '.join(args.exclude)}")

    else:
        # Classic mode: scope.json path supplied directly.
        scope_path = args.scope
        if not scope_path.exists():
            print(f"ERROR: scope.json not found: {scope_path}", file=sys.stderr)
            sys.exit(1)
        try:
            scope = load_scope(scope_path)
        except (ValidationError, Exception) as exc:
            print(f"ERROR: Invalid scope.json: {exc}", file=sys.stderr)
            sys.exit(1)
        outdir = args.outdir  # may be None — run_agent will derive it

    run_agent(
        scope_path=scope_path,
        outdir=outdir,
        max_iterations=args.max_iterations,
        resume_dir=args.resume,
        model=args.model,
        num_ctx=args.num_ctx,
        max_batch_size=args.max_batch_size,
    )


if __name__ == "__main__":
    main()
