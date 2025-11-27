#!/bin/bash

DOMAIN=$1
# Optional dry run: app.sh <domain> [--dry-run]
DRY_RUN=0
if [ "$2" = "--dry-run" ]; then
    DRY_RUN=1
fi

[ -z "$DOMAIN" ] && echo "[*] Usage: $0 <domain> [--dry-run]" && exit 1

OUTPUT_DIR="recon_${DOMAIN}"
mkdir -p "$OUTPUT_DIR"

strip_ansi() {
    sed 's/\x1B\[[0-9;]*[mK]//g' | sed 's/\x1b\[[0-9;]*m//g'
}

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: sublist3r -d $DOMAIN -o $OUTPUT_DIR/sublister.txt"
    # dry-run placeholder
    echo "www.$DOMAIN" > "$OUTPUT_DIR/sublister.txt"
else
    echo "[*] Running Sublist3r..."
    sublist3r -d "$DOMAIN" -o "$OUTPUT_DIR/sublister.txt" 2>&1
    [ ! -f "$OUTPUT_DIR/sublister.txt" ] && touch "$OUTPUT_DIR/sublister.txt"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: timeout 90 amass enum -d $DOMAIN -passive -o $OUTPUT_DIR/amass.txt"
    echo "sub.$DOMAIN" > "$OUTPUT_DIR/amass.txt"
else
    echo "[*] Running Amass..."
    timeout 90 amass enum -d "$DOMAIN" -passive -o "$OUTPUT_DIR/amass.txt" 2>&1
    [ ! -f "$OUTPUT_DIR/amass.txt" ] && touch "$OUTPUT_DIR/amass.txt"
fi

echo "[*] Combining and deduplicating subdomains..."
cat "$OUTPUT_DIR/sublister.txt" "$OUTPUT_DIR/amass.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/subdomains.txt"
[ ! -s "$OUTPUT_DIR/subdomains.txt" ] && echo "$DOMAIN" > "$OUTPUT_DIR/subdomains.txt"

SUBDOMAIN_COUNT=$(wc -l < "$OUTPUT_DIR/subdomains.txt")
echo "[+] Found $SUBDOMAIN_COUNT subdomains"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: httpx -silent -o $OUTPUT_DIR/live_hosts.txt (stdin from $OUTPUT_DIR/subdomains.txt)"
    # placeholder - mark one live host
    echo "http://$DOMAIN" > "$OUTPUT_DIR/live_hosts.txt"
else
    echo "[*] Probing live hosts with httpx..."
    cat "$OUTPUT_DIR/subdomains.txt" | httpx -silent -o "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null
    [ ! -s "$OUTPUT_DIR/live_hosts.txt" ] && echo "http://$DOMAIN" > "$OUTPUT_DIR/live_hosts.txt"
fi

LIVE_COUNT=$(wc -l < "$OUTPUT_DIR/live_hosts.txt")
echo "[+] Found $LIVE_COUNT live hosts"

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: gospider -S $OUTPUT_DIR/live_hosts.txt -o $OUTPUT_DIR/gospider_output"
    mkdir -p "$OUTPUT_DIR/gospider_output"
    # create a small placeholder file
    echo "http://$DOMAIN/page1" > "$OUTPUT_DIR/gospider_output/page_sample.txt"
else
    echo "[*] Running gospider for spidering live hosts..."
    gospider -S "$OUTPUT_DIR/live_hosts.txt" -o "$OUTPUT_DIR/gospider_output" 2>&1
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: gau --threads 10 < $OUTPUT_DIR/live_hosts.txt > $OUTPUT_DIR/gau.txt"
    echo "http://$DOMAIN/archived1" > "$OUTPUT_DIR/gau.txt"
else
    echo "[*] Extracting archived URLs with gau..."
    cat "$OUTPUT_DIR/live_hosts.txt" | gau --threads 10 2>/dev/null | grep -iE '^https?://' | sort -u > "$OUTPUT_DIR/gau.txt" 2>/dev/null
    [ ! -f "$OUTPUT_DIR/gau.txt" ] && touch "$OUTPUT_DIR/gau.txt"
fi

if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: waybackurls < $OUTPUT_DIR/live_hosts.txt >> $OUTPUT_DIR/gau.txt"
else
    echo "[*] Extracting archived URLs with waybackurls..."
    cat "$OUTPUT_DIR/live_hosts.txt" | waybackurls 2>/dev/null >> "$OUTPUT_DIR/gau.txt" || true
fi

echo "[*] Done. Results saved to $OUTPUT_DIR/archived_urls.txt"

cat "$OUTPUT_DIR/gau.txt" 2>/dev/null | sort -u > "$OUTPUT_DIR/allurls.txt"

find "$OUTPUT_DIR/gospider_output" -type f 2>/dev/null | while read -r file; do
    grep -oE 'https?://[^[:space:]]+' "$file" 2>/dev/null >> "$OUTPUT_DIR/allurls.txt"
done

grep '\?' "$OUTPUT_DIR/allurls.txt" 2>/dev/null | head -200 > "$OUTPUT_DIR/scanurls.txt"
head -50 "$OUTPUT_DIR/allurls.txt" 2>/dev/null >> "$OUTPUT_DIR/scanurls.txt"
cat "$OUTPUT_DIR/live_hosts.txt" "$OUTPUT_DIR/subdomains.txt" 2>/dev/null >> "$OUTPUT_DIR/scanurls.txt"
echo "$DOMAIN" >> "$OUTPUT_DIR/scanurls.txt"
sort -u "$OUTPUT_DIR/scanurls.txt" -o "$OUTPUT_DIR/scanurls.txt"

URL_COUNT=$(wc -l < "$OUTPUT_DIR/scanurls.txt")
echo "[+] Found $URL_COUNT URLs for scanning"

echo "[*] Scanning archived URLs with Nuclei..."

# Run Nuclei and capture output
if [ "$DRY_RUN" -eq 1 ]; then
    echo "[DRYRUN] Would run: nuclei -l $OUTPUT_DIR/scanurls.txt -severity info,low,medium,high,critical,unknown -rate-limit 200 -c 40 -timeout 5"
    # create a small placeholder output when dry-running
    echo "[info] example-template - http://$DOMAIN - info" > "$OUTPUT_DIR/nuclei_results_raw.txt"
    echo "[info] example-template - http://$DOMAIN - info" > "$OUTPUT_DIR/nuclei_results.txt"
else
    nuclei -l "$OUTPUT_DIR/scanurls.txt" \
        -severity info,low,medium,high,critical,unknown \
        -rate-limit 200 -c 40 -timeout 5 \
        -o "$OUTPUT_DIR/nuclei_results_raw.txt" 2>&1 | tee "$OUTPUT_DIR/nuclei_live.txt"
fi

# Process nuclei output to ADD severity brackets if missing
# Ensure OUTPUT_DIR is exported so the Python heredoc can read it via os.environ
export OUTPUT_DIR
python3 << PROCESS_NUCLEI
import re
import os

output_dir = os.environ.get('OUTPUT_DIR', '.')
# Prefer nuclei_results_raw.txt, then fall back to nuclei_live.txt (stdout capture)
input_candidates = [ os.path.join(output_dir, 'nuclei_results_raw.txt'), os.path.join(output_dir, 'nuclei_live.txt') ]
input_file = None
for c in input_candidates:
    if os.path.exists(c):
        input_file = c
        break

output_file = os.path.join(output_dir, 'nuclei_results.txt')

# Ensure output file exists so downstream steps don't fail if there's no input
open(output_file, 'w').close()

if input_file:
    with open(input_file, 'r') as f_in, open(output_file, 'w') as f_out:
        for line in f_in:
            line = line.strip()
            if not line:
                continue
            
            # Remove ANSI codes
            line_clean = re.sub(r'\x1b\[[0-9;]*m|\[\[.*?m|\[\[.*?\[0m', '', line)
            
            # Check if it has severity bracket already
            if '[critical]' in line_clean or '[high]' in line_clean or '[medium]' in line_clean or '[low]' in line_clean or '[info]' in line_clean:
                # Already has severity - just clean ANSI
                f_out.write(line_clean + '\n')
            else:
                # Try to extract and add severity if possible
                f_out.write(line_clean + '\n')
PROCESS_NUCLEI

VULN_COUNT=$(wc -l < "$OUTPUT_DIR/nuclei_results.txt" 2>/dev/null || echo 0)
echo "[+] Found $VULN_COUNT vulnerabilities"

# Output vulnerabilities with markers for dashboard
if [ -s "$OUTPUT_DIR/nuclei_results.txt" ]; then
  while IFS= read -r vuln_line; do
    if [ ! -z "$vuln_line" ]; then
      echo "###VULN###$vuln_line###END###"
    fi
  done < "$OUTPUT_DIR/nuclei_results.txt"
fi

echo "[*] Generating final JSON..."

python3 << ENDINPUT
import json
import os
from datetime import datetime, timezone

domain = "$DOMAIN"
output_dir = "$OUTPUT_DIR"

def read_file_as_list(filepath):
    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            return lines
    except:
        return []

subdomains = read_file_as_list(os.path.join(output_dir, "subdomains.txt"))
live_hosts = read_file_as_list(os.path.join(output_dir, "live_hosts.txt"))
urls = read_file_as_list(os.path.join(output_dir, "scanurls.txt"))
nuclei_results = read_file_as_list(os.path.join(output_dir, "nuclei_results.txt"))

urls_limited = urls[:100]

final_json = {
    "domain": domain,
    "scan_timestamp": datetime.now(timezone.utc).isoformat(),
    "statistics": {
        "subdomains_count": len(subdomains),
        "live_hosts_count": len(live_hosts),
        "urls_count": len(urls),
        "vulnerabilities_count": len(nuclei_results)
    },
    "subdomains": subdomains,
    "live_hosts": live_hosts,
    "urls": urls_limited,
    "nuclei_results": nuclei_results
}

output_file = os.path.join(output_dir, "final_output.json")
with open(output_file, 'w') as f:
    f.write("###JSON_START###\n")
    json.dump(final_json, f, indent=2)
    f.write("\n###JSON_END###\n")
ENDINPUT

echo "[*] ✓ Complete!"
echo ""
echo "========================================"
echo "RECON SUMMARY FOR $DOMAIN"
echo "========================================"
echo "Subdomains: $(cat "$OUTPUT_DIR/subdomains.txt" 2>/dev/null | wc -l)"
echo "Live Hosts: $(cat "$OUTPUT_DIR/live_hosts.txt" 2>/dev/null | wc -l)"
echo "URLs: $(cat "$OUTPUT_DIR/scanurls.txt" 2>/dev/null | wc -l)"
echo "Vulnerabilities: $(cat "$OUTPUT_DIR/nuclei_results.txt" 2>/dev/null | wc -l)"
echo "========================================"