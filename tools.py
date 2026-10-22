"""
tools.py

One wrapper function per recon CLI tool.  Each wrapper:
  1. Builds a subprocess command from fixed, scope-derived parameters.
  2. Runs it with a per-tool timeout.
  3. Writes stdout+stderr to raw/<tool>_<target>_<timestamp>.txt —
     UNCONDITIONALLY, even on non-zero exit or timeout.
  4. Returns the raw output path and exit status to the caller.

Design constraints (from the build spec):
  - Rate / aggressiveness parameters (threads, delay, wordlist, crawl depth,
    etc.) come ONLY from scope.json — never from model-supplied tool args.
  - Each wrapper is single-call and concurrency-unaware; all scheduling
    happens in executor.py.
  - Tool schemas exposed to the model live at the bottom of this file as a
    list of Ollama-compatible tool dicts.
"""

from __future__ import annotations

import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from scope import Constraints


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------


@dataclass
class ToolResult:
    tool: str
    target: str          # primary target as passed to the wrapper
    raw_path: Path       # path to the unconditionally written raw output file
    exit_code: int       # 0 = success, non-zero = failure, -1 = timeout
    timed_out: bool = False
    error_message: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _run(
    cmd: list[str],
    raw_path: Path,
    timeout: int,
    tool: str,
    target: str,
) -> ToolResult:
    """
    Run *cmd* as a subprocess, stream stdout+stderr to *raw_path*, and
    return a ToolResult.  Writes the raw file unconditionally.
    """
    raw_path.parent.mkdir(parents=True, exist_ok=True)

    timed_out = False
    exit_code = -1
    error_message = ""

    try:
        with open(raw_path, "w", encoding="utf-8", errors="replace") as fh:
            # Write the command line at the top so the raw file is self-documenting.
            fh.write(f"# command: {shlex.join(cmd)}\n")
            fh.write(f"# tool: {tool}  target: {target}\n")
            fh.write(f"# started: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n\n")
            fh.flush()

            proc = subprocess.Popen(
                cmd,
                stdout=fh,
                stderr=fh,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
            try:
                proc.wait(timeout=timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                timed_out = True
                exit_code = -1
                error_message = f"Timed out after {timeout}s"
                fh.write(f"\n# TIMEOUT after {timeout}s\n")

    except Exception as exc:  # noqa: BLE001
        error_message = str(exc)
        exit_code = -1
        # Still write *something* to the raw file so the path is valid.
        try:
            with open(raw_path, "a", encoding="utf-8", errors="replace") as fh:
                fh.write(f"\n# WRAPPER ERROR: {exc}\n")
        except Exception:
            pass

    return ToolResult(
        tool=tool,
        target=target,
        raw_path=raw_path,
        exit_code=exit_code,
        timed_out=timed_out,
        error_message=error_message,
    )


def _raw_path(outdir: Path, tool: str, target: str) -> Path:
    """Build a deterministic raw output path."""
    # Sanitise target for use in filenames.
    safe_target = target.replace("/", "_").replace(":", "_").replace("*", "WILD")
    safe_target = safe_target[:80]  # cap length
    ts = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    return outdir / "raw" / f"{tool}_{safe_target}_{ts}.txt"


# ---------------------------------------------------------------------------
# Tool wrappers
# ---------------------------------------------------------------------------


def run_subfinder(
    targets: list[str],
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """
    Passive subdomain enumeration.
    targets: list of domains (subfinder supports -dL for a file; we use -d
             repeatedly for small lists, or write a temp file for large ones).
    """
    tool = "subfinder"
    target_str = ",".join(targets)
    raw = _raw_path(outdir, tool, target_str[:60])
    timeout = constraints.get_timeout(tool)

    # Write targets to a temp file so subfinder can consume them.
    target_file = outdir / "raw" / f"subfinder_targets_{int(time.time())}.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = ["subfinder", "-dL", str(target_file), "-silent", "-all", "-o", "/dev/stdout"]
    return _run(cmd, raw, timeout, tool, target_str)


def run_ffuf(
    target: str,
    outdir: Path,
    constraints: Constraints,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
) -> ToolResult:
    """
    Directory/content discovery.  Wordlist is a scope-level config, not a
    model-supplied argument.
    """
    tool = "ffuf"
    raw = _raw_path(outdir, tool, target)
    timeout = constraints.get_timeout(tool)

    # Ensure the URL has a scheme.
    url = target if target.startswith("http") else f"https://{target}"
    url = url.rstrip("/") + "/FUZZ"

    cmd = [
        "ffuf",
        "-u", url,
        "-w", wordlist,
        "-mc", "200,301,302,403",
        "-of", "json",
        "-o", "/dev/stdout",
        "-s",  # silent mode — progress to stderr, results to stdout
    ]
    return _run(cmd, raw, timeout, tool, target)


def run_gau(
    targets: list[str],
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Fetch known URLs from AlienVault OTX, Wayback Machine, etc."""
    tool = "gau"
    target_str = ",".join(targets)
    raw = _raw_path(outdir, tool, target_str[:60])
    timeout = constraints.get_timeout(tool)

    # gau reads domains from stdin, one per line.
    target_file = outdir / "raw" / f"gau_targets_{int(time.time())}.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = [
        "bash", "-c",
        f"cat {shlex.quote(str(target_file))} | gau --threads 3 --timeout 30",
    ]
    return _run(cmd, raw, timeout, tool, target_str)


def run_httpx(
    targets: list[str],
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Probe targets for live HTTP services."""
    tool = "httpx"
    target_str = ",".join(targets)
    raw = _raw_path(outdir, tool, target_str[:60])
    timeout = constraints.get_timeout(tool)

    target_file = outdir / "raw" / f"httpx_targets_{int(time.time())}.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = [
        "httpx",
        "-l", str(target_file),
        "-silent",
        "-mc", "200,301,302,403",
    ]
    return _run(cmd, raw, timeout, tool, target_str)


def run_katana(
    targets: list[str],
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Active crawl / parameter mining."""
    tool = "katana"
    target_str = ",".join(targets)
    raw = _raw_path(outdir, tool, target_str[:60])
    timeout = constraints.get_timeout(tool)

    target_file = outdir / "raw" / f"katana_targets_{int(time.time())}.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = [
        "katana",
        "-list", str(target_file),
        "-jc",                          # JS crawling
        "-d", str(constraints.crawl_depth),
        "-c", "3",                      # concurrency fixed by scope, not model
        "-o", "/dev/stdout",
    ]
    return _run(cmd, raw, timeout, tool, target_str)


def run_getjs(
    targets: list[str],
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Extract JS file URLs from live pages (must run before linkfinder)."""
    tool = "getJS"
    target_str = ",".join(targets)
    raw = _raw_path(outdir, tool, target_str[:60])
    timeout = constraints.get_timeout(tool)

    target_file = outdir / "raw" / f"getjs_targets_{int(time.time())}.txt"
    target_file.parent.mkdir(parents=True, exist_ok=True)
    target_file.write_text("\n".join(targets) + "\n", encoding="utf-8")

    cmd = ["getJS", "--input", str(target_file), "--output", "/dev/stdout"]
    return _run(cmd, raw, timeout, tool, target_str)


def run_linkfinder(
    js_file_url: str,
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Parse a single JS file for embedded endpoints/parameters."""
    tool = "linkfinder"
    raw = _raw_path(outdir, tool, js_file_url)
    timeout = constraints.get_timeout(tool)

    cmd = ["linkfinder", "-i", js_file_url, "-o", "cli"]
    return _run(cmd, raw, timeout, tool, js_file_url)


def run_gf(
    pattern: str,
    input_file: Path,
    outdir: Path,
    constraints: Constraints,
) -> ToolResult:
    """Apply a gf pattern to a URL list file and surface matching candidates."""
    tool = "gf"
    raw = _raw_path(outdir, tool, pattern)
    timeout = constraints.get_timeout(tool)

    cmd = ["bash", "-c", f"cat {shlex.quote(str(input_file))} | gf {shlex.quote(pattern)}"]
    return _run(cmd, raw, timeout, tool, pattern)


def run_pattern_dedupe(
    input_file: Path,
    output_file: Path,
    outdir: Path,
    constraints: Constraints,
    max_per_pattern: int = 1,
) -> ToolResult:
    """
    Shell out to the existing pattern_dedupe.py as the pipeline does.
    Keeps the deduplication logic in one canonical place.
    """
    tool = "pattern_dedupe"
    raw = _raw_path(outdir, tool, input_file.name)
    timeout = constraints.get_timeout(tool)

    # Locate pattern_dedupe.py relative to this file.
    script = Path(__file__).parent / "pattern_dedupe.py"

    cmd = [
        sys.executable,
        str(script),
        str(input_file),
        str(output_file),
        "--max-per-pattern", str(max_per_pattern),
    ]
    return _run(cmd, raw, timeout, tool, input_file.name)


# ---------------------------------------------------------------------------
# Tool registry — maps tool name string to wrapper callable
# ---------------------------------------------------------------------------

# Used by executor.py and agent.py to dispatch tool calls by name.
TOOL_REGISTRY: dict[str, object] = {
    "subfinder": run_subfinder,
    "ffuf": run_ffuf,
    "gau": run_gau,
    "httpx": run_httpx,
    "katana": run_katana,
    "getJS": run_getjs,
    "linkfinder": run_linkfinder,
    "gf": run_gf,
    "pattern_dedupe": run_pattern_dedupe,
}


# ---------------------------------------------------------------------------
# Ollama tool schemas (exposed to the model)
# ---------------------------------------------------------------------------
#
# IMPORTANT constraints encoded here:
#   - Rate / aggressiveness / thread-count / crawl-depth are NOT in any
#     tool's parameter schema — they come from scope.json only.
#   - Tools that naturally take multiple targets (subfinder, httpx, gau,
#     katana) expose a `targets` list parameter so the model can request
#     N domains in one call instead of N round-trips.
#   - linkfinder and gf take single string inputs by design.

TOOL_SCHEMAS: list[dict] = [
    {
        "type": "function",
        "function": {
            "name": "subfinder",
            "description": (
                "Passive subdomain enumeration via multiple public sources. "
                "Accepts a list of root domains; returns discovered subdomains. "
                "Does not hit the target directly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of root domains to enumerate subdomains for.",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ffuf",
            "description": (
                "Directory/content discovery via wordlist fuzzing on a single target "
                "URL or domain. Reveals hidden paths and files. "
                "Use after confirming a target is live (httpx)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target domain or URL (e.g. 'target.com' or 'https://target.com').",
                    },
                },
                "required": ["target"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gau",
            "description": (
                "Fetch historically known URLs for one or more domains from "
                "AlienVault OTX, Wayback Machine, and similar sources. "
                "Passive — does not hit the target directly."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domains to look up historical URLs for.",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "httpx",
            "description": (
                "Probe one or more hosts/URLs to confirm they are live HTTP(S) services. "
                "Returns only URLs responding with 200/301/302/403. "
                "Run this before active crawlers (katana) to avoid wasting requests on dead hosts."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of domains or URLs to probe.",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "katana",
            "description": (
                "Active web crawl: follows links, executes JS, mines parameters. "
                "Produces large output — always run pattern_dedupe afterwards. "
                "Only run on targets confirmed live by httpx."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of live URLs or domains to crawl.",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "getJS",
            "description": (
                "Extract all JavaScript file URLs referenced by one or more pages. "
                "Run this BEFORE linkfinder — linkfinder needs actual JS file content, "
                "not page HTML."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "targets": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of live page URLs to extract JS file URLs from.",
                    },
                },
                "required": ["targets"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "linkfinder",
            "description": (
                "Parse a single JavaScript file to find embedded endpoints and parameters. "
                "Run once per JS file URL; results complement Katana's HTML-crawl findings."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "js_file_url": {
                        "type": "string",
                        "description": "URL of a single JavaScript file to parse.",
                    },
                },
                "required": ["js_file_url"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "gf",
            "description": (
                "Apply a vulnerability-class pattern to a URL list file. "
                "Patterns: xss, ssrf, sqli, idor, lfi, redirect, rce. "
                "Input must be a path to a file (e.g. the master_urls.txt from the "
                "pattern_dedupe step)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "enum": ["xss", "ssrf", "sqli", "idor", "lfi", "redirect", "rce"],
                        "description": "Vulnerability class pattern to match.",
                    },
                    "input_file": {
                        "type": "string",
                        "description": "Absolute path to the URL list file to filter.",
                    },
                },
                "required": ["pattern", "input_file"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "pattern_dedupe",
            "description": (
                "Collapse a URL list by (path + sorted-param-name) signature, "
                "turning tens of thousands of crawled URLs into a reviewable few hundred "
                "to low thousands. Always run this after katana or any large crawler output."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "input_file": {
                        "type": "string",
                        "description": "Absolute path to the input URL list.",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Absolute path where deduplicated output should be written.",
                    },
                    "max_per_pattern": {
                        "type": "integer",
                        "description": "Max representative URLs to keep per unique pattern (default 1).",
                        "default": 1,
                    },
                },
                "required": ["input_file", "output_file"],
            },
        },
    },
]
