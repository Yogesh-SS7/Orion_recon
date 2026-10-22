# Build Spec: Scoped Recon Orchestration Agent (Hybrid A/B — concurrent execution)

## Context

You're building the orchestration layer for an authorized bug-bounty / pentest
recon pipeline. The recon tools themselves (subfinder, ffuf, gau, httpx,
katana, getJS, linkfinder, gf) already exist and are installed on the target
Linux box. What's missing is the **agent layer**: an LLM-driven loop that
decides which tool to call next, enforces scope before and after every call,
parses raw tool output into structured digests, and feeds those digests back
to the model so it can reason about what to do next — ending in a ranked,
explained candidate list, not a raw pass-through of tool output.

Two files already exist and should be treated as fixed, working reference
code — read them, don't rewrite them:

- `pattern_dedupe.py` — collapses URLs by `(scheme, netloc, normalized-path,
  sorted-param-names)` signature. This is the mechanism that turns tens of
  thousands of crawled URLs into a reviewable few-hundred-to-low-thousands
  candidate list. `agent.py`'s `tools.py` wrapper for katana/gau output should
  shell out to this script exactly as `recon_pipeline.sh` already does.
- `recon_pipeline.sh` — the non-agentic, linear bash version of this pipeline.
  Treat it as the spec for *what each tool does and in what order*, not as
  something to port line-for-line. The agent replaces the fixed bash
  sequencing with an LLM deciding the sequence, inside guardrails.

## Objective

Build a Python CLI agent (`agent.py` as entrypoint) that:

1. Takes a `scope.json` describing the authorized target(s) and constraints.
2. Lets an LLM (local Ollama, `qwen2.5:7b`, native tool use) propose a
   **batch** of tool calls per turn — not necessarily just one.
3. Validates every proposed call against scope **before** executing it.
4. Runs the allowed calls in a **bounded, concurrent worker pool**, with a
   rate limiter that holds regardless of how many calls fire at once.
5. Always writes raw output to disk, unconditionally, per call, as soon as
   that call completes — not gated on the rest of the batch finishing.
6. Parses raw output into structured JSON per tool, per call, as it lands.
7. Re-checks scope on anything a tool *discovered* that wasn't in the
   original request (e.g. katana following a link to a new subdomain) —
   out-of-scope discoveries are flagged and surfaced, never silently dropped
   or silently included.
7a. On a failed call (non-zero exit, timeout, or unparseable output), allows
   the model to retry that exact `(tool, target)` up to a fixed cap — then,
   once the cap is hit, **pauses the run and asks the operator directly in
   the terminal** what to do next, rather than leaving retry behavior to the
   model's own judgment or silently giving up. See "Failure handling &
   human escalation (MVP)" below — this is deliberately a thin, bounded
   mechanism for v1; classifying *why* a call failed and adapting strategy
   based on that is explicitly deferred to v2.
8. Once the batch settles (all calls complete, or a partial-batch timeout
   elapses), builds **one compact digest covering the whole batch** and
   appends it back into the model's conversation as a single tool-result
   turn — not one digest per call.
9. Logs every full batch turn (model message, every call in the batch, the
   combined digest) as one JSON object per line in `agent.log`, so a crashed
   run can be resumed.
10. Terminates on a final answer or `--max-iterations`, and writes
    `summary.md`.

## Tech stack

- **Language:** Python 3.11+, stdlib-first. `subprocess` for tool execution,
  `json` for all structured data, `argparse` for the CLI.
- **LLM integration:** local **Ollama**, via the `ollama` Python package
  (`ollama.chat(..., tools=[...])`) or the raw `POST /api/chat` REST
  endpoint — not the Anthropic SDK. Use Ollama's native tool-calling
  support (the `tools` parameter + `tool_calls` in the response), not a
  hand-rolled JSON-in-prose scheme. A single response can contain multiple
  `tool_calls` entries; treat that list as the batch.
  - **Pinned model: `qwen2.5:7b`.** Make the model name/tag a config value
    (CLI flag or config file, not hardcoded) so it's easy to swap later, but
    `qwen2.5:7b` is the default to build and test against.
  - **Set `num_ctx` explicitly — do not rely on Ollama's default.** Ollama
    defaults to a 2048-token context window regardless of what the
    underlying model supports; Qwen2.5:7B supports up to 32K natively, but
    that's only usable if `num_ctx` is set explicitly, either in a custom
    Modelfile or per-request via `options={"num_ctx": N}`. Left at the
    default, the agent will silently truncate conversation history mid-run
    with no error — just the model "forgetting" earlier turns/digests. Pick
    an `num_ctx` value that's a config constant (e.g. 8192 or 16384,
    whatever the hardware comfortably supports) and document why it's set
    where it's set.
  - **At 7B, tool-call reliability needs active handling, not just
    validation-as-a-formality.** Smaller models are more prone to malformed
    args, wrong tool names, or dropping a call's required field, especially
    as the number of calls proposed in one batch grows. Two concrete
    implications for this build:
    - Treat the validate-then-retry path from the model-choice note below
      as a required part of the loop, not optional error handling — expect
      to hit it regularly, not as a rare edge case.
    - Keep the model-proposable batch size modest by default (e.g. cap how
      many tool calls the agent will accept from a single turn, separately
      from `max_concurrent_calls` which caps the *executor's* concurrency)
      — a 7B model reasoning correctly about 2–4 simultaneous calls is a
      safer bet than trusting it with 10+ at once. Make this cap a config
      value too.
  - **Validate before trusting.** Every incoming `tool_call` from Ollama
    should go through the same `pydantic` validation as everything else in
    this build before it reaches the dedup/scope gates — if args fail to
    validate (missing field, wrong type, unknown tool name), reject the
    call with a clear error folded into the batch digest and let the model
    retry, rather than letting a malformed call reach `executor.py`.
  - **Even with `num_ctx` raised, keep digests tight.** Batch-level (not
    per-call) digests matter even more here — keep digests as compact as
    the rule-based summarizer in `ingest.py` can make them, since the
    context budget is a fixed, explicit number you set above, not an
    elastic hosted-API ceiling, and it's fixed by whatever the hardware
    comfortably supports.
- **Concurrency:** `concurrent.futures.ThreadPoolExecutor` is sufficient —
  these are subprocess calls (I/O-bound waiting on external CLI tools), not
  CPU-bound work, so threads over a bounded pool are enough. Don't reach for
  `asyncio` unless a tool wrapper specifically needs it; keep the executor
  layer simple.
- **Schema validation:** `pydantic` (v2) for `scope.json`, tool-call
  arguments, and parsed-output shapes. This replaces ad hoc dict checking and
  makes the "fail loud, not silently" requirement enforceable — a pydantic
  `ValidationError` is exactly the kind of explicit failure the digest
  discipline below requires.
- **No web framework, no database.** This is a CLI tool that runs on an
  operator's Linux box against their own filesystem. State lives in the
  output folder.
- **No test scripts.** Testing happens manually against live tooling on a
  Linux machine the developer already has recon tools installed on — do not
  generate `pytest` suites, mocked subprocess tests, or CI config. Focus
  entirely on the implementation. (If you want to leave manual smoke-test
  *instructions* as a comment or in a README, that's fine — just not
  automated test code.)

## Architecture

```
<outdir>/
  scope.json          # input, authored by operator before run starts
  raw/                 # unconditional raw tool output, one file per call
  parsed/               # structured JSON per tool call, from parsers
  agent.log            # JSONL — one object per BATCH turn, append-only
  summary.md           # final output, written at loop end or on resume-exit
```

### Module breakdown

**`scope.py`**
- `Scope` pydantic model: target domain(s)/subdomain(s)/IP ranges in scope,
  explicitly out-of-scope exclusions, any rate/concurrency constraints the
  operator has set (these are the *ceiling*, not a suggestion — see below).
- `ScopeChecker` class with two methods:
  - `check_input(target: str) -> ScopeDecision` — called before any tool
    executes, blocks out-of-scope calls outright.
  - `check_discovery(urls_or_hosts: list[str]) -> list[ScopeDecision]` —
    called after parsing tool output, flags (not silently drops) anything
    newly discovered that falls outside scope.
- Folder identity: the output directory name is derived from a stable hash
  of the *content* of `scope.json` (not engagement name + timestamp). Same
  scope content → same/continuing folder across runs. Any change to
  `scope.json` → new folder. This is a deliberate guard against an operator
  accidentally fragmenting one engagement's output across multiple
  `--outdir` invocations.

**`tools.py`**
- One wrapper function per CLI tool (subfinder, ffuf, gau, httpx, katana,
  getJS, linkfinder, gf, plus a wrapper that shells out to the existing
  `pattern_dedupe.py`).
- Tool schemas exposed to the model: tools that support batch targets
  (subfinder, httpx) should still accept a list of targets in their
  parameter schema, so the model can request N domains in one call instead
  of N round-trips — this is independent of, and stacks with, the batch
  concurrency `executor.py` provides across *different* tool calls.
- **Rate/aggressiveness parameters (thread count, delay, wordlist choice,
  crawl depth, etc.) are never exposed as model-controllable tool
  parameters.** They're pulled from `scope.json`'s constraints block and
  hardcoded into the subprocess invocation inside each wrapper. The model
  can choose *which* tool to run and *what target*, not how hard to hit it,
  and not how many of them run at once — that's `executor.py`'s job.
- Every wrapper: build the subprocess command → run with a timeout
  (configurable, sane default e.g. 10 min, tool-specific overrides allowed in
  scope.json) → write stdout/stderr to `raw/<tool>_<target>_<timestamp>.txt`
  unconditionally, even on non-zero exit or timeout → return the raw file
  path and exit status to the caller. The wrapper itself does not parse and
  does not know whether it's being run solo or inside a concurrent batch —
  that distinction lives entirely in `executor.py`.

**`executor.py`** (new in this hybrid design)
- Owns the worker pool and the rate limiter — `tools.py` wrappers stay
  single-call, unaware of concurrency; `executor.py` is the only place that
  schedules them.
- `run_batch(calls: list[ToolCall]) -> Iterator[ToolCallResult]` — takes the
  list of scope-approved, dedup-approved calls for one model turn, runs them
  through a `ThreadPoolExecutor`, and yields results **as each call
  completes**, not after the whole batch finishes. The caller (`agent.py`)
  uses each result immediately to trigger that call's parse + disk-write +
  discovery scope-check, so a slow call never blocks already-finished ones
  from landing in `raw/`/`parsed/`.
- **Rate limiting: per-tool, not global.** A single global token bucket
  would either throttle passive/API-backed tools (subfinder, gau) to match
  the safe ceiling for active scanners (ffuf, katana), or let active
  scanners slip through under a ceiling sized for passive tools — neither is
  right. Implement one token-bucket limiter per tool name, each keyed off
  `scope.json.constraints.rate_limits.<tool>.max_requests_per_min` (or an
  equivalent per-tool field — see schema below). A sensible built-in default
  if a tool has no explicit entry: conservative (e.g. passive tools ~60
  req/min, active scanners ~10–20 req/min) — but always let `scope.json`
  override it; never hardcode without a config escape hatch.
- **Concurrency cap: bounded worker pool, size from
  `scope.json.constraints.max_concurrent_calls`,** default small (3–5) if
  unset. This caps *how many tool calls run simultaneously across the whole
  batch*, independent of each tool's own per-call thread/rate settings
  (which, per `tools.py` above, are themselves fixed by scope, not the
  model).
- The limiter and pool together mean: the model submitting 10 calls in one
  batch must never result in those 10 calls collectively exceeding the rate
  ceiling a sequential, one-call-at-a-time run would have respected. The
  model's batch intent changes *throughput/ordering*, never the ceiling.
- Every call is still individually timeout-capped exactly as in the
  non-concurrent design — the pool doesn't change per-call timeout
  semantics, only how many calls are in flight waiting on their timeouts at
  once.

**`ingest.py`**
- One parser function per tool, each taking a raw output path and returning
  a pydantic model instance written to `parsed/<tool>_<target>.json`.
- **Explicit fail-path requirement:** if a parser cannot make sense of the
  raw output (unexpected format, tool crashed mid-write, empty-but-tool-said-
  success, etc.), it must raise or return a tagged failure object — never a
  silently empty/default result that would read in the digest as "zero
  findings," because that's indistinguishable from a real negative result.
  The digest-builder downstream must render parser failures as visibly
  different from real empty results (e.g. `"status": "unparseable", "raw":
  "raw/katana_target_ts.txt"` vs `"status": "ok", "count": 0`).
- A `build_digest(parsed_result) -> str` function per tool, used as a
  building block — but the thing actually appended to the model's
  conversation is a **batch-level** digest. Add a
  `build_batch_digest(results: list[ToolCallResult]) -> str` in `ingest.py`
  (or `agent.py`, whichever reads cleaner) that concatenates/condenses the
  per-call digests of everything in the batch into one tool-result message.
  This keeps context usage roughly flat as batch size grows, instead of
  scaling linearly with the number of calls the model happened to submit in
  one turn. Still rule-based, still deterministic — not another LLM call.

**`agent.py`** (entrypoint)
- CLI args: `scope.json` path, `--outdir` (optional — defaults to the
  scope-hash-derived folder), `--max-iterations`, `--resume <outdir>`.
- Core loop:

```
load scope.json → ScopeChecker
if --resume: replay agent.log (JSONL) to reconstruct conversation + tool
             state, pick up where the last complete turn left off
else: start fresh conversation with system prompt describing available
      tools, scope summary, and the overall objective (sanitized candidate
      list + per-candidate reasoning, mirroring agent_recon_workflow.md's
      Phase 6 agent responsibilities)

loop until final answer or max_iterations:
    model proposes a BATCH of tool_call(s) in one turn (one or more)

    # gating pass — sequential, cheap, before anything hits the executor
    approved = []
    for call in batch:
        call_state = lookup (tool, normalized_target) in session call-state
                     table (see "Failure handling" below) — one of:
                     NEVER_RUN | SUCCEEDED | FAILED_BELOW_CAP | ESCALATED
        if call_state == SUCCEEDED: reject, point the model at the
                     existing parsed/ file instead of re-running
        elif call_state == ESCALATED: reject — this call already went
                     through human escalation this session (see below);
                     do not re-prompt the operator for the same call twice
                     in one run unless they explicitly chose "retry" last
                     time, which resets it to FAILED_BELOW_CAP
        else:  # NEVER_RUN or FAILED_BELOW_CAP
            scope.check_input(target) → if out-of-scope, reject with reason,
                         do not execute
            if passes scope: approved.append(call)
    rejected calls get their reasons folded into the batch digest directly
                     (no need to run them to explain why they didn't run)

    # concurrent execution pass
    results = []
    for result in executor.run_batch(approved):   # yields as each completes
        raw output already written unconditionally to raw/ by this point
                     (executor/tools.py writes it before yielding the result)
        ingest.py parser → parsed/<tool>_<target>.json
                     (explicit failure path, never silent default)
        update session call-state table for (tool, target):
                     success → SUCCEEDED
                     failure → increment failure_count; if failure_count
                     < max_retries_per_call → FAILED_BELOW_CAP, else →
                     pending escalation (handled after the batch settles,
                     not mid-executor-run — see below)
        newly-discovered hosts/URLs in parsed output →
                     scope.check_discovery(...) → out-of-scope discoveries
                     flagged, not dropped
        results.append(parsed_result_with_flags)
        # note: results.append happens per-call as it streams in; nothing
        # here waits for the rest of the batch

    # batch settles (all approved calls complete, or partial-batch timeout)

    # human escalation — runs AFTER the concurrent batch has fully settled,
    # never while other workers are still in flight. One blocking prompt
    # per newly-escalated call, sequential (stdin can't multiplex).
    for call in results where this batch just pushed it past the retry cap:
        print a clear summary to the terminal: tool, target, attempt count,
                     exit code / timeout / unparseable, path to raw/ output
        prompt operator: skip this call and continue / retry once more /
                     abort the whole run
        record the operator's choice in the session call-state table and
                     in agent.log (see schema below)
        if operator chose "abort": write summary.md with everything
                     gathered so far, exit immediately — do not return to
                     the model for a final turn

    batch_digest = build_batch_digest(results + rejected_call_reasons +
                     escalation_outcomes)
    append batch_digest to conversation as ONE tool-result turn
    append this full batch turn (model message + every call in the batch +
                     combined digest + any escalation outcomes) to
                     agent.log as one JSON object, flush to disk
                     immediately (not buffered) so a crash loses at most
                     the in-flight batch, never prior turns

on loop exit: write summary.md — ranked candidate list with per-candidate
              reasoning (why it matched, false-positive considerations per
              vuln class per agent_recon_workflow.md's Phase 6 table),
              a section listing any out-of-scope discoveries that were
              flagged during the run, and a section listing every call that
              required human escalation and what the operator chose
```

### Failure handling & human escalation (MVP — v1 scope)

Deliberately thin for v1. What this build DOES do:

- Track a **failure count per `(tool, normalized_target)`**, in-memory for
  the session (persisted into `agent.log` so `--resume` can reconstruct it —
  see schema below).
- On failure, the digest line is a **fixed, terse format** — tool, target,
  attempt N of `max_retries_per_call`, exit code or `"timeout"` or
  `"unparseable"`, and the `raw/` file path. The model sees enough to decide
  whether to retry the same call (allowed, up to the cap) or move on to
  something else — but the harness is not analyzing *why* it failed for the
  model.
- `max_retries_per_call` lives in `scope.json.constraints`, same as every
  other bound in this system — not something the model can raise or lower.
- **Once a call hits the cap, the agent blocks and prompts the operator
  directly in the terminal** (plain `input()` is fine for v1 — no need for
  a fancier TUI). Offer exactly three choices, kept deliberately simple:
  - **skip** — mark this call as permanently failed for the session, fold
    that into the digest so the model knows not to expect this data, and
    continue the loop.
  - **retry** — reset this call's failure count to 0 and allow the model to
    attempt it again next turn (useful when the operator just fixed
    something out-of-band, e.g. started a VPN, fixed a wordlist path).
  - **abort** — stop the whole run immediately, write `summary.md` with
    whatever's been gathered so far, exit. Do not go back to the model for
    a closing turn.
- The prompt is per-call and sequential — if a batch produces more than one
  escalation at once (possible now that batches run concurrently), the
  operator is prompted once per escalated call, in order, not all at once.

What this build explicitly does NOT do (deferred to v2):

- No parsing or classification of *why* a call failed (auth error vs.
  rate-limited vs. binary missing vs. network unreachable vs. target
  genuinely down). v1 only distinguishes "it failed" + a raw pointer.
- No automatic adaptation based on failure type (e.g. auto-lowering thread
  count on a suspected rate-limit, auto-skipping a tool whose binary isn't
  found). That reasoning is v2's job, once there's a classified error signal
  to reason over.
- No non-blocking/background escalation mode. v1 is a single interactive
  terminal session — the operator is expected to be present and able to
  respond to a blocking prompt when it appears. A `--non-interactive` mode
  that defaults all escalations to "skip" and logs them for later review is
  a reasonable v2 addition, not a v1 requirement.

### Data contracts

**`scope.json`** (pydantic `Scope` model) — minimum fields:
```json
{
  "in_scope": ["target.com", "*.target.com"],
  "out_of_scope": ["staging.target.com"],
  "constraints": {
    "max_concurrent_calls": 4,
    "max_retries_per_call": 2,
    "request_delay_ms": 0,
    "crawl_depth": 2,
    "tool_timeout_seconds": {"katana": 1800, "ffuf": 900},
    "rate_limits": {
      "subfinder": {"max_requests_per_min": 60},
      "gau": {"max_requests_per_min": 60},
      "httpx": {"max_requests_per_min": 30},
      "ffuf": {"max_requests_per_min": 15},
      "katana": {"max_requests_per_min": 15}
    }
  }
}
```
`rate_limits` is per-tool deliberately (see `executor.py` above) —
`max_concurrent_calls` is the one global knob, and it caps simultaneous
calls across the whole batch, not requests-per-tool.

**`agent.log`** — JSONL, one object per **batch turn** (not per call):
```json
{
  "turn": 7,
  "timestamp": "...",
  "model_message": "...",
  "tool_calls": [
    {"tool": "katana", "args": {...}, "scope_decision": "allowed",
     "raw_path": "raw/...", "parsed_path": "parsed/...",
     "discoveries_flagged": [], "status": "ok", "attempt": 1},
    {"tool": "ffuf", "args": {...}, "scope_decision": "rejected",
     "reason": "target not in scope.in_scope", "status": "not_run"},
    {"tool": "httpx", "args": {...}, "scope_decision": "allowed",
     "raw_path": "raw/...", "status": "failed", "attempt": 3,
     "escalated": true, "operator_choice": "retry"}
  ],
  "batch_digest": "..."
}
```
`attempt` tracks which retry this call represents for its `(tool, target)`
pair; `escalated`/`operator_choice` only appear on the turn where the
retry cap was hit and the operator was prompted — this is what `--resume`
reads back to reconstruct the session's failure-count table.

### Non-goals for this build (explicitly deferred)

Do not implement these — stub or comment that they're deferred, don't build
partial versions:

- **Multi-phase batch planning** — the model proposes one batch per turn and
  reacts to the combined digest before proposing the next; it does not plan
  several batches ahead without seeing intermediate results. (Concurrent
  execution *within* a turn's batch is in scope — this non-goal is about the
  model's planning horizon, not the executor.)
- Any model-controlled rate, concurrency, thread-count, or crawl-depth
  parameter — these always come from `scope.json` only, never from the
  model's tool-call arguments, batched or not.
- A web UI or API server — CLI only.
- Automated tests of any kind.
- `asyncio`-based execution — the `ThreadPoolExecutor` approach in
  `executor.py` is sufficient for this subprocess-bound workload; don't
  introduce an async runtime for this build.
- Any classification of *why* a tool call failed, or automated strategy
  changes based on that classification — see "Failure handling & human
  escalation (MVP)" above. v1 only tracks pass/fail + a retry count; the
  operator, not the agent, decides what a failure means.
- A non-interactive / background escalation mode — v1 assumes an operator
  is present at the terminal for the whole run.

### Optional, if time allows (v1.1 — build after the above is solid)

- Content-hash raw output (not just `(tool, target)`) so a rerun after a
  minor scope.json change can skip re-parsing identical output.
- A hard per-session tool-call budget (count and/or wall-clock time),
  enforced independently of `--max-iterations`, since a single long-running
  tool call isn't bounded by the iteration counter.

## Deliverable

`scope.py`, `tools.py`, `executor.py`, `ingest.py`, `agent.py`, wired
together per the batch loop above, using the existing `pattern_dedupe.py`
as-is. Ask before making any architectural change to the loop structure,
scope-enforcement points, per-tool rate-limiting design, or digest-discipline
rules described above — those are deliberate design decisions, not open
questions.
