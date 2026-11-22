# Orion Recon — Autonomous Recon Orchestration Agent

Orion Recon is an autonomous reconnaissance agent designed for authorized penetration testing and bug-bounty assessments. It coordinates industry-standard security CLI tools into an iterative decision loop driven by local LLMs (via Ollama), backed by strict boundary enforcement and concurrency controls.

---

## Key Features

- **Strict Scope Boundary Enforcement**: Pre-execution validation blocks out-of-scope targets before tools are invoked. Exclusions always take precedence over wildcards.
- **Concurrent Execution & Rate Limiting**: Token-bucket algorithm regulates request velocity per tool across thread pools to prevent target instability or IP bans.
- **Pattern Deduplication**: Collapses tens of thousands of duplicate URL shapes into concise, high-signal parameter lists.
- **Human-in-the-Loop Escalation**: Automatically halts and prompts the operator if a tool fails repeatedly or hits retry thresholds.
- **Resumable State**: Preserves execution state in `agent.log` to resume interrupted or crashed sessions without repeating completed steps.

---

## Recon Pipeline Workflow

1. **Subdomain Enumeration**: `subfinder` passive reconnaissance.
2. **Historical URL Mining**: `gau` (Wayback Machine, AlienVault, URLScan).
3. **Liveness Probing**: `httpx` HTTP server verification.
4. **Path & Content Discovery**: `ffuf` directory fuzzing on live hosts.
5. **Active Crawling**: `katana` route and parameter extraction.
6. **URL Deduplication**: `pattern_dedupe.py` normalizes dynamic parameters.
7. **JavaScript Endpoint Analysis**: `getJS` extracts scripts; `linkfinder` discovers embedded endpoints.
8. **Vulnerability Classification**: `gf` pattern matching (SSRF, XSS, SQLi, IDOR, LFI, RCE).

---

## Installation & Prerequisites

1. **Python 3.11+**
   ```bash
   pip install -r requirements.txt
   ```
2. **Ollama** (Local LLM Server)
   ```bash
   ollama pull qwen2.5:7b
   ollama serve
   ```
3. **Security CLI Tools**: Install required tools (`subfinder`, `ffuf`, `httpx`, `gau`, `katana`, `gf`) into your system `PATH`.

---

## Usage

### 1. Quick Mode (Single Target)
```bash
python agent.py --target example.com
```
Exclude subdomains directly from the CLI:
```bash
python agent.py --target example.com --exclude staging.example.com internal.example.com
```

### 2. Full Scope Mode (`scope.json`)
Define fine-grained targets, exclusions, rate limits, and timeouts:
```bash
python agent.py scope.json
```

Example `scope.json`:
```json
{
  "in_scope": [
    "example.com"
  ],
  "out_of_scope": [
    "*.example.com",
    "staging.example.com"
  ],
  "constraints": {
    "max_concurrent_calls": 4,
    "max_retries_per_call": 2,
    "crawl_depth": 2,
    "rate_limits": {
      "subfinder": { "max_requests_per_min": 60 },
      "httpx": { "max_requests_per_min": 30 },
      "katana": { "max_requests_per_min": 15 }
    }
  }
}
```

### 3. Resuming a Run
```bash
python agent.py scope.json --resume recon_13ece8616c7c/
```
