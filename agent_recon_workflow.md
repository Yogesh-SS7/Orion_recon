# Recon Pipeline — Workflow Spec for Agent Build

**Goal:** turn a raw target domain into a small, high-signal candidate list
(hundreds, not tens of thousands) that an AI agent can review for likely
vulnerable parameters — same logic a human would run manually, now
scripted end to end except for the final manual Burp step.

Companion files: `recon_pipeline.sh` (full script), `pattern_dedupe.py`
(the dedupe engine, called by the script — must sit in the same folder).

---

## Phase 1 — Discovery (subfinder + ffuf)

```bash
subfinder -d target.com -silent -all -o subs_raw.txt
sort -u subs_raw.txt -o subs.txt

ffuf -u https://target.com/FUZZ -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,301,302,403 -of csv -o ffuf_raw.csv -s
```

**Output:** `subs.txt` (subdomains), `ffuf_urls.txt` (discovered paths on root domain).

---

## Phase 2 — GAU (historical URLs)

```bash
cat subs.txt | gau --threads 3 --timeout 30 > gau_raw.txt
```

**Output:** `gau_raw.txt` — large, noisy, includes static assets and
duplicate-shape URLs (same endpoint, different id/page values).

---

## Dedupe Stage 1 — Combine + strip static noise

```bash
cat subs.txt ffuf_urls.txt gau_raw.txt | sort -u > combined_raw.txt

grep -Ev '\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map|pdf|mp4|zip)(\?|$)' \
    combined_raw.txt > combined_clean.txt
```

**What this does:** exact-line dedupe (`sort -u`) removes byte-identical
duplicates. The `grep -Ev` strips anything ending in a static-asset
extension — these can never carry an injectable parameter, so they're
pure noise for vuln-hunting purposes.

**What this does NOT do:** collapse `?id=1`, `?id=2`, `?id=3`... into one
entry. That's handled later (see Dedupe Stage 2) — doing it here is
premature since we haven't crawled yet.

---

## Phase 3 — HTTPX (confirm live targets)

```bash
cat combined_clean.txt | httpx -silent -mc 200,301,302,403 -o live_urls.txt
```

**Why before Katana:** no point spending crawl time/requests on dead
hosts. This step is a cost-control gate, not a dedupe step.

---

## Phase 4 — Katana (active crawl / parameter mining)

```bash
katana -list live_urls.txt -jc -d 2 -c 3 -o katana_raw.txt
```

This is the step that produces the "80k endpoints" problem — katana
follows every link, every JS-discovered route, at every crawl depth.
Raw output is expected to be huge and mostly redundant.

---

## Dedupe Stage 2 — Sanitize Katana output (the 80k → 1–2k step)

This is the critical stage. Three passes, in order:

```bash
# Pass A — exact dedupe
sort -u katana_raw.txt -o katana_sorted.txt

# Pass B — strip static assets again (katana finds plenty more)
grep -Ev '\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map|pdf|mp4|zip)(\?|$)' \
    katana_sorted.txt > katana_clean.txt

# Pass C — keep only URLs that actually carry parameters
grep '?' katana_clean.txt > katana_with_params.txt

# Pass D — PATTERN-LEVEL dedupe (the real noise killer)
python3 pattern_dedupe.py katana_with_params.txt katana_patterns.txt --max-per-pattern 1
```

**Why Pass D matters more than A–C combined:** `sort -u` only removes
*byte-identical* lines. It does nothing about:

```
/product?id=1001
/product?id=1002
/product?id=1003
   ...x thousands
```

These are 1,000+ "unique" lines by `sort -u`'s definition, but they're
really **one endpoint** worth testing once. `pattern_dedupe.py` groups
URLs by `(host, normalized-path, sorted-param-names)` — collapsing
numeric path segments too (`/user/123/profile` → `/user/{n}/profile`) —
and keeps only one representative URL per unique signature. This is
the actual mechanism that turns 80,000 raw lines into a few hundred to
low thousands of genuinely distinct things to look at.

Tune reduction aggressiveness with `--max-per-pattern` (default 1; set
to 2–3 if you want a couple of real value examples per pattern instead
of just one).

---

## Phase 5/6 — JS mining: getJS (extractor) → LinkFinder

**Order matters:** getJS must run first — LinkFinder parses JS file
*contents*, it doesn't fetch anything itself.

```bash
getJS --input live_urls.txt --output js_files.txt

> linkfinder_raw.txt
while read -r js; do
    linkfinder -i "$js" -o cli >> linkfinder_raw.txt
done < js_files.txt

sort -u linkfinder_raw.txt -o linkfinder_raw.txt
grep '?' linkfinder_raw.txt > linkfinder_with_params.txt
```

This surfaces endpoints hardcoded in JS that never appear in crawled
HTML — a meaningfully different source than Katana's link-following.

---

## Final Merge + Dedupe

```bash
cat katana_patterns.txt linkfinder_with_params.txt | sort -u > master_pre_dedupe.txt
python3 pattern_dedupe.py master_pre_dedupe.txt master_urls.txt --max-per-pattern 1
```

Run pattern-dedupe again post-merge, since Katana and LinkFinder can
surface overlapping endpoint shapes from different discovery paths.

**`master_urls.txt` is the deliverable of the automated half of this
pipeline** — a sanitized, pattern-deduped candidate list, realistically
in the hundreds-to-low-thousands range even on a large target.

---

## Phase 6 (continued) — gf pattern-match → per-vuln-class shortlists

```bash
mkdir -p gf_results
for pattern in xss ssrf sqli idor lfi redirect rce; do
    cat master_urls.txt | gf "$pattern" > "gf_results/gf_${pattern}.txt"
done
```

**This is where the AI agent's job starts.** Each `gf_results/gf_*.txt`
file is a shortlist of candidates matching a vuln-class signature.
The agent's role here mirrors what a human analyst does manually:

- For each candidate URL, reason about *why* it matched (param name,
  reflection likelihood, context)
- Cross-reference against known false-positive patterns (e.g. `gf rce`
  matching `searchQuery` purely because it contains "query" — a
  pattern match is a hypothesis, not a finding)
- Rank/triage candidates by plausibility before any human or further
  automated testing touches them
- Flag anything worth a manual Burp look, and explain why

---

## Phase 7 — Burp analysis (manual, NOT automated)

Intentionally excluded from the script. This remains a human-in-the-loop
step: authenticated flows, multi-step forms, session-state-dependent
parameters, and actual payload testing/confirmation stay manual
regardless of how good the agent's triage gets.

---

## Summary: what the agent actually receives

| File | Contents | Agent's job |
|---|---|---|
| `master_urls.txt` | Full sanitized, pattern-deduped candidate list | Available as full context if needed |
| `gf_results/gf_xss.txt` | XSS-pattern candidates | Reason about reflection likelihood, rank |
| `gf_results/gf_ssrf.txt` | SSRF-pattern candidates | Check for URL/host-like param values |
| `gf_results/gf_sqli.txt` | SQLi-pattern candidates | Flag search/filter/sort params especially |
| `gf_results/gf_idor.txt` | IDOR-pattern candidates | Flag sequential/numeric ID params |
| `gf_results/gf_lfi.txt` | LFI-pattern candidates | Flag file/path/template-like params |
| `gf_results/gf_redirect.txt` | Open-redirect candidates | Flag full-URL-as-value params |
| `gf_results/gf_rce.txt` | RCE-pattern candidates | **High false-positive rate** — treat as lowest-confidence category, needs most scrutiny |

The agent should output a ranked shortlist with reasoning per candidate,
not a raw pass-through of gf's output — that reasoning step is the
actual value-add over the plain bash pipeline.
