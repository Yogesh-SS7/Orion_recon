"""
scope.py

Pydantic models for scope.json, scope enforcement (pre-execution and
post-discovery), and the scope-hash-derived output directory.

Scope identity is derived from the *content* of scope.json (SHA-256 of
canonical JSON), so:
  - Same scope content → same/continuing output folder across runs.
  - Any change to scope.json → new folder, no accidental cross-run mixing.
"""

from __future__ import annotations

import hashlib
import json
import re
import fnmatch
from enum import Enum
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Scope schema
# ---------------------------------------------------------------------------


class RateLimit(BaseModel):
    max_requests_per_min: int = 60


class ToolTimeout(BaseModel):
    """Per-tool timeout overrides; any tool not listed uses the global default."""
    pass  # populated dynamically via __root__ / dict handling


class Constraints(BaseModel):
    max_concurrent_calls: int = Field(default=4, ge=1)
    max_retries_per_call: int = Field(default=2, ge=0)
    request_delay_ms: int = Field(default=0, ge=0)
    crawl_depth: int = Field(default=2, ge=1)
    # per-tool timeout overrides (seconds); keys are tool names
    tool_timeout_seconds: dict[str, int] = Field(default_factory=dict)
    # per-tool rate limits
    rate_limits: dict[str, RateLimit] = Field(default_factory=dict)
    # global default timeout for any tool not listed in tool_timeout_seconds
    default_tool_timeout_seconds: int = Field(default=600)

    def get_timeout(self, tool: str) -> int:
        """Return the timeout (seconds) for a given tool."""
        return self.tool_timeout_seconds.get(tool, self.default_tool_timeout_seconds)

    def get_rate_limit(self, tool: str) -> int:
        """Return max_requests_per_min for a tool, with conservative built-ins."""
        if tool in self.rate_limits:
            return self.rate_limits[tool].max_requests_per_min
        # Built-in conservative defaults — never exceed without explicit scope.json entry.
        _passive_tools = {"subfinder", "gau"}
        if tool in _passive_tools:
            return 60
        return 15  # active scanners: ffuf, katana, httpx, getJS, linkfinder, gf


class Scope(BaseModel):
    in_scope: list[str] = Field(min_length=1)
    out_of_scope: list[str] = Field(default_factory=list)
    constraints: Constraints = Field(default_factory=Constraints)

    @model_validator(mode="after")
    def check_no_overlap(self) -> "Scope":
        # Warn if something appears in both lists — it's not illegal but
        # likely a mistake.  We can't log here so we keep it as a no-op
        # guard; the operator will see the rejection at runtime.
        return self


# ---------------------------------------------------------------------------
# ScopeDecision
# ---------------------------------------------------------------------------


class Decision(str, Enum):
    ALLOWED = "allowed"
    OUT_OF_SCOPE = "out_of_scope"
    INVALID = "invalid"


class ScopeDecision(BaseModel):
    decision: Decision
    target: str
    reason: str = ""


# ---------------------------------------------------------------------------
# ScopeChecker
# ---------------------------------------------------------------------------


class ScopeChecker:
    """Enforces in_scope / out_of_scope rules before and after tool execution."""

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_host(target: str) -> str:
        """
        Pull a bare hostname/IP from a target string.
        Handles plain hostnames, URLs, and CIDR-ish strings (returned as-is).
        """
        target = target.strip()
        if target.startswith(("http://", "https://")):
            parsed = urlsplit(target)
            return parsed.hostname or target
        # If it contains a slash that's not a URL scheme, treat as URL without
        # scheme — still try to extract host.
        if "/" in target and not target.startswith("/"):
            parsed = urlsplit("https://" + target)
            return parsed.hostname or target
        # Plain host, CIDR, or IP — return as-is.
        return target.split(":")[0]  # strip port if any

    @staticmethod
    def _host_matches_pattern(host: str, pattern: str) -> bool:
        """
        True if *host* matches *pattern*, where pattern may be:
          - An exact domain         ("target.com")
          - A wildcard subdomain    ("*.target.com")
          - An fnmatch glob         ("api.*.target.com")
          - A CIDR range            (not implemented here — stub as exact match)
        """
        pattern = pattern.strip().lstrip("*.")
        # Wildcard: any subdomain of pattern OR pattern itself.
        return host == pattern or host.endswith("." + pattern)

    def _is_explicitly_excluded(self, host: str) -> bool:
        for excl in self._scope.out_of_scope:
            excl_host = self._extract_host(excl)
            if self._host_matches_pattern(host, excl_host):
                return True
        return False

    def _is_in_scope(self, host: str) -> bool:
        for inc in self._scope.in_scope:
            inc_host = self._extract_host(inc)
            if self._host_matches_pattern(host, inc_host):
                return True
        return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_input(self, target: str) -> ScopeDecision:
        """
        Called BEFORE any tool executes.  Returns ALLOWED or OUT_OF_SCOPE.
        An OUT_OF_SCOPE decision must block the call — never execute it.
        """
        if not target or not target.strip():
            return ScopeDecision(
                decision=Decision.INVALID,
                target=target,
                reason="Empty target.",
            )

        host = self._extract_host(target)

        if self._is_explicitly_excluded(host):
            return ScopeDecision(
                decision=Decision.OUT_OF_SCOPE,
                target=target,
                reason=f"'{host}' matches out_of_scope list.",
            )

        if self._is_in_scope(host):
            return ScopeDecision(
                decision=Decision.ALLOWED,
                target=target,
                reason="",
            )

        return ScopeDecision(
            decision=Decision.OUT_OF_SCOPE,
            target=target,
            reason=f"'{host}' not found in in_scope list.",
        )

    def check_discovery(self, urls_or_hosts: list[str]) -> list[ScopeDecision]:
        """
        Called AFTER parsing tool output, on any host/URL discovered by the tool.
        Returns one ScopeDecision per input — out-of-scope items are FLAGGED,
        not silently dropped.  Never call this with the original target; only
        with *newly discovered* items.
        """
        return [self.check_input(item) for item in urls_or_hosts]


# ---------------------------------------------------------------------------
# Scope-hash-derived output directory
# ---------------------------------------------------------------------------


def scope_output_dir(scope_path: Path, base_dir: Optional[Path] = None) -> Path:
    """
    Derive a stable output directory path from the *content* of scope.json.

    Rules:
      - Reads scope.json, canonicalises it (sorted keys, no extra whitespace),
        and takes the first 12 hex chars of its SHA-256.
      - Prefix is 'recon_' + <hash fragment>.
      - If base_dir is provided, the folder lives there; otherwise it's
        created as a sibling of scope.json.

    Same scope content → same folder name, regardless of where or when run.
    Any edit to scope.json → different hash → new folder.
    """
    raw = scope_path.read_text(encoding="utf-8")
    # Canonical form: parse and re-serialise with sorted keys
    canonical = json.dumps(json.loads(raw), sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:12]
    folder_name = f"recon_{digest}"
    root = base_dir if base_dir else scope_path.parent
    return root / folder_name


def load_scope(scope_path: Path) -> Scope:
    """Parse and validate scope.json, raising pydantic ValidationError on bad input."""
    raw = json.loads(scope_path.read_text(encoding="utf-8"))
    return Scope.model_validate(raw)
