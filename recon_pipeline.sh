#!/bin/bash
# =====================================================================
# Recon Pipeline — Agent-Ready Workflow
# Produces a clean, sanitized candidate-parameter list for AI/human
# triage. Every stage dedupes before handing off to the next.
#
# Usage: ./recon_pipeline.sh target.com
# Requires: subfinder, ffuf, gau, httpx, katana, getJS, linkfinder, gf,
#           python3 (for pattern_dedupe.py, must be in same folder)
# =====================================================================
set -e

if [ -z "$1" ]; then
    echo "Usage: $0 <target-domain>"
    exit 1
fi

TARGET="$1"
WORKDIR="./recon_${TARGET}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

mkdir -p "$WORKDIR"
cd "$WORKDIR"

echo "=== [PHASE 1] Subdomain + initial path discovery ==="

# 1a. subfinder — passive subdomain enumeration
subfinder -d "$TARGET" -silent -all -o subs_raw.txt
sort -u subs_raw.txt -o subs.txt
echo "    subfinder: $(wc -l < subs.txt) unique subdomains"

# 1b. ffuf — directory/content discovery on the root domain
#     (quick pass; swap wordlist path for your preferred list)
ffuf -u "https://${TARGET}/FUZZ" \
     -w /usr/share/wordlists/dirb/common.txt \
     -mc 200,301,302,403 -of csv -o ffuf_raw.csv -s || true
# pull just the discovered paths out of ffuf's csv into plain url list
tail -n +2 ffuf_raw.csv 2>/dev/null | cut -d',' -f1 > ffuf_urls.txt || touch ffuf_urls.txt
echo "    ffuf: $(wc -l < ffuf_urls.txt) paths found"

echo ""
echo "=== [PHASE 2] GAU — historical URLs ==="

cat subs.txt | gau --threads 3 --timeout 30 > gau_raw.txt
echo "    gau: $(wc -l < gau_raw.txt) raw URLs"

echo ""
echo "=== [DEDUPE 1] Combine subfinder/ffuf/gau output, strip static noise ==="

cat subs.txt ffuf_urls.txt gau_raw.txt | sort -u > combined_raw.txt

# Strip static assets — never carry injectable params
grep -Ev '\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map|pdf|mp4|zip)(\?|$)' \
    combined_raw.txt > combined_clean.txt

echo "    combined: $(wc -l < combined_raw.txt) -> clean: $(wc -l < combined_clean.txt)"

echo ""
echo "=== [PHASE 3] HTTPX — confirm live targets ==="

cat combined_clean.txt | httpx -silent -mc 200,301,302,403 -o live_urls.txt
echo "    live: $(wc -l < live_urls.txt) confirmed-alive URLs"

echo ""
echo "=== [PHASE 4] Katana — active crawl / param mining ==="

katana -list live_urls.txt -jc -d 2 -c 3 -o katana_raw.txt
echo "    katana raw: $(wc -l < katana_raw.txt) endpoints"

echo ""
echo "=== [DEDUPE 2] Sanitize katana output (this is the 80k -> 1-2k step) ==="

sort -u katana_raw.txt -o katana_sorted.txt

grep -Ev '\.(css|js|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot|ico|map|pdf|mp4|zip)(\?|$)' \
    katana_sorted.txt > katana_clean.txt

grep '?' katana_clean.txt > katana_with_params.txt
echo "    with-params: $(wc -l < katana_with_params.txt)"

# THE key reduction step — collapse by path+param-signature, not full URL.
# This is what actually gets you from tens of thousands down to a
# reviewable candidate list.
python3 "$SCRIPT_DIR/pattern_dedupe.py" katana_with_params.txt katana_patterns.txt --max-per-pattern 1

echo ""
echo "=== [PHASE 5/6] JS mining: getJS (extractor) -> LinkFinder ==="

# getJS first (JS-extractor) — must run before LinkFinder, which needs
# actual JS file contents to parse, not just URLs.
getJS --input live_urls.txt --output js_files.txt
echo "    JS files found: $(wc -l < js_files.txt)"

> linkfinder_raw.txt
while read -r js; do
    linkfinder -i "$js" -o cli >> linkfinder_raw.txt 2>/dev/null || true
done < js_files.txt

sort -u linkfinder_raw.txt -o linkfinder_raw.txt
grep '?' linkfinder_raw.txt > linkfinder_with_params.txt || touch linkfinder_with_params.txt
echo "    JS-derived endpoints with params: $(wc -l < linkfinder_with_params.txt)"

echo ""
echo "=== [FINAL MERGE] Combine katana patterns + JS-derived params ==="

cat katana_patterns.txt linkfinder_with_params.txt | sort -u > master_pre_dedupe.txt
python3 "$SCRIPT_DIR/pattern_dedupe.py" master_pre_dedupe.txt master_urls.txt --max-per-pattern 1

echo "    FINAL master_urls.txt: $(wc -l < master_urls.txt) candidate URLs"
echo "    (this is the sanitized file ready for gf / agent review)"

echo ""
echo "=== [PHASE 6 continued] gf pattern-match (candidate shortlist by vuln class) ==="

mkdir -p gf_results
for pattern in xss ssrf sqli idor lfi redirect rce; do
    cat master_urls.txt | gf "$pattern" > "gf_results/gf_${pattern}.txt" 2>/dev/null || true
    count=$(wc -l < "gf_results/gf_${pattern}.txt" 2>/dev/null || echo 0)
    echo "    gf $pattern: $count candidates"
done

echo ""
echo "=== DONE ==="
echo "Final outputs in: $WORKDIR"
echo "  master_urls.txt       -> full sanitized candidate list"
echo "  gf_results/*.txt      -> per-vuln-class shortlist (feed these to the AI agent)"
echo ""
echo "NOTE: Phase 7 (Burp manual analysis) is intentionally NOT automated here."
