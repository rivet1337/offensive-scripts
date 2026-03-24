#!/bin/zsh
# ============================================================
# Nuclei Test Cases - From basic to advanced
# Usage: ./test_nuclei.sh [test_number]
#   e.g. ./test_nuclei.sh 1    (run test 1 only)
#        ./test_nuclei.sh       (run all tests)
# ============================================================

export GOROOT=~/go-install/go
export GOPATH=~/go
export PATH=$GOROOT/bin:$GOPATH/bin:$PATH

TARGET="http://scanme.nmap.org"  # Safe, legal test target
RESULTS_DIR="$HOME/offensive-scripts/nuclei_test_results"
mkdir -p "$RESULTS_DIR"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Live status line — shows last line of output, overwrites in place
live_run() {
    "$@" 2>&1 | while IFS= read -r line; do
        printf "\r\033[K  \033[36m%s\033[0m" "${line:0:120}"
    done
    printf "\r\033[K"
}

run_test() {
    local num="$1"
    local name="$2"
    shift 2
    echo ""
    echo "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo "${CYAN}${BOLD}  TEST $num: $name${NC}"
    echo "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
    echo "${YELLOW}CMD:${NC} $@"
    echo ""
}

pass() { echo "\n${GREEN}${BOLD}[PASS]${NC} $1\n"; }
fail() { echo "\n${RED}${BOLD}[FAIL]${NC} $1\n"; }

SELECTED="${1:-all}"

# ===========================================================
# TEST 1: Sanity check — does nuclei even run?
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "1" ]]; then
    run_test 1 "Sanity Check - Version & Template Count" \
        "nuclei -version && nuclei -tl 2>&1 | wc -l"

    live_run nuclei -version
    TMPL_COUNT=$(nuclei -tl 2>&1 | grep -c "")
    echo "Total templates available: $TMPL_COUNT"

    if [[ $TMPL_COUNT -gt 100 ]]; then
        pass "Nuclei installed with $TMPL_COUNT templates"
    else
        fail "Template count too low ($TMPL_COUNT) — run: nuclei -update-templates"
    fi
fi

# ===========================================================
# TEST 2: Basic single-host scan (info severity only — fast)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "2" ]]; then
    OUTPUT="$RESULTS_DIR/test2_basic.txt"
    run_test 2 "Basic Single Host Scan (info only)" \
        "nuclei -u $TARGET -severity info -stats -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -severity info \
        -stats \
        -timeout 10 \
        -rl 50 \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        FINDINGS=$(wc -l < "$OUTPUT")
        pass "Got $FINDINGS info-level findings → $OUTPUT"
        echo "${YELLOW}Sample findings:${NC}"
        head -5 "$OUTPUT"
    else
        fail "No output produced. Check if target is reachable: curl -sI $TARGET"
    fi
fi

# ===========================================================
# TEST 3: Technology detection scan (-tags tech)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "3" ]]; then
    OUTPUT="$RESULTS_DIR/test3_techdetect.txt"
    JSON_OUT="$RESULTS_DIR/test3_techdetect.json"
    run_test 3 "Technology Detection" \
        "nuclei -u $TARGET -tags tech -je $JSON_OUT -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -tags tech \
        -timeout 10 \
        -rl 50 \
        -je "$JSON_OUT" \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        pass "Tech detection complete → $OUTPUT"
        cat "$OUTPUT"
    else
        fail "No tech detected (target may not expose tech headers)"
    fi
fi

# ===========================================================
# TEST 4: Auto-scan mode (-as) — fingerprint then scan
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "4" ]]; then
    OUTPUT="$RESULTS_DIR/test4_autoscan.txt"
    run_test 4 "Auto-Scan Mode (tech fingerprint → targeted templates)" \
        "nuclei -u $TARGET -as -stats -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -as \
        -stats \
        -timeout 10 \
        -rl 50 \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        FINDINGS=$(wc -l < "$OUTPUT")
        pass "Auto-scan found $FINDINGS results → $OUTPUT"
        head -10 "$OUTPUT"
    else
        echo "${YELLOW}[INFO]${NC} No auto-scan findings (normal for hardened targets)"
    fi
fi

# ===========================================================
# TEST 5: Specific template test (http-missing-security-headers)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "5" ]]; then
    OUTPUT="$RESULTS_DIR/test5_headers.txt"
    run_test 5 "Specific Template - Missing Security Headers" \
        "nuclei -u $TARGET -id http-missing-security-headers -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -id http-missing-security-headers \
        -timeout 10 \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        pass "Missing header detection works → $OUTPUT"
        cat "$OUTPUT"
    else
        fail "Template didn't match (unexpected for most targets)"
    fi
fi

# ===========================================================
# TEST 6: JSON output parsing (verify report pipeline works)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "6" ]]; then
    JSON_OUT="$RESULTS_DIR/test6_json.json"
    run_test 6 "JSON Output & Parsing" \
        "nuclei -u $TARGET -severity info -je $JSON_OUT -limit 10"

    live_run nuclei -u "$TARGET" \
        -severity info \
        -timeout 10 \
        -rl 50 \
        -je "$JSON_OUT" \
        -limit 10

    if [[ -s "$JSON_OUT" ]]; then
        ENTRIES=$(wc -l < "$JSON_OUT")
        pass "JSON output has $ENTRIES entries → $JSON_OUT"
        echo "${YELLOW}Parsed fields from first entry:${NC}"
        head -1 "$JSON_OUT" | python3 -m json.tool 2>/dev/null | head -20
    else
        fail "No JSON output produced"
    fi
fi

# ===========================================================
# TEST 7: Stealth mode simulation (low rate, custom headers)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "7" ]]; then
    OUTPUT="$RESULTS_DIR/test7_stealth.txt"
    run_test 7 "Stealth Mode (rate-limit 30, host-spray, custom UA)" \
        "nuclei -u $TARGET -severity info -rl 30 -c 3 -bs 3 -ss host-spray -H 'User-Agent: ...' -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -severity info \
        -rl 30 \
        -c 3 \
        -bs 3 \
        -ss host-spray \
        -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" \
        -H "Accept-Language: en-US,en;q=0.5" \
        -timeout 10 \
        -stats \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        pass "Stealth scan produced results → $OUTPUT"
        head -5 "$OUTPUT"
    else
        echo "${YELLOW}[INFO]${NC} Stealth scan completed (may have fewer results due to rate limiting)"
    fi
fi

# ===========================================================
# TEST 8: Proxy mode (dry run — just verify flag is accepted)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "8" ]]; then
    run_test 8 "Proxy Flag Acceptance (no actual proxy needed)" \
        "nuclei -u $TARGET -id http-missing-security-headers -proxy socks5://127.0.0.1:9999 -timeout 3"

    # This will fail to connect (no proxy running) but should NOT error on the flag itself
    OUTPUT=$(nuclei -u "$TARGET" \
        -id http-missing-security-headers \
        -proxy socks5://127.0.0.1:9999 \
        -timeout 3 2>&1)
    printf "\r\033[K"

    if echo "$OUTPUT" | grep -qi "unknown flag\|invalid\|unrecognized"; then
        fail "Nuclei doesn't recognize -proxy flag"
    else
        pass "Proxy flag accepted (connection failed as expected — no proxy running)"
    fi
fi

# ===========================================================
# TEST 9: Community templates with cent
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "9" ]]; then
    run_test 9 "Community Templates via Cent" \
        "cent -p ~/cent-nuclei-templates && nuclei -u $TARGET -t ~/cent-nuclei-templates -severity info -limit 5"

    CENT_DIR="$HOME/cent-nuclei-templates"

    # Check if cent is installed
    if ! command -v cent &>/dev/null; then
        echo "${YELLOW}Installing cent...${NC}"
        live_run go install -v github.com/xm1k3/cent/v2@latest
    fi

    # Create cent config if missing (v2 uses ~/.config/cent/.cent.yaml)
    CENT_CONFIG="$HOME/.config/cent/.cent.yaml"
    if [[ ! -f "$CENT_CONFIG" ]]; then
        echo "${YELLOW}Creating cent v2 config...${NC}"
        mkdir -p "$HOME/.config/cent"
        live_run cent init
        echo "Created $CENT_CONFIG"
    fi

    # Pull community templates
    if [[ ! -d "$CENT_DIR" ]] || [[ $(find "$CENT_DIR" -name "*.yaml" 2>/dev/null | wc -l) -lt 10 ]]; then
        echo "${YELLOW}Pulling community templates (this may take a minute)...${NC}"
        live_run cent -p "$CENT_DIR"
    fi

    YAML_COUNT=$(find "$CENT_DIR" -name "*.yaml" 2>/dev/null | wc -l)
    echo "Community templates available: $YAML_COUNT"

    if [[ $YAML_COUNT -gt 50 ]]; then
        OUTPUT="$RESULTS_DIR/test9_community.txt"
        echo "${YELLOW}Running nuclei with community templates...${NC}"
        live_run nuclei -u "$TARGET" \
            -t "$CENT_DIR" \
            -severity info \
            -timeout 10 \
            -rl 50 \
            -limit 10 \
            -o "$OUTPUT"

        if [[ -s "$OUTPUT" ]]; then
            FINDINGS=$(wc -l < "$OUTPUT")
            pass "Community template scan: $FINDINGS findings → $OUTPUT"
            head -5 "$OUTPUT"
        else
            echo "${YELLOW}[INFO]${NC} Community scan completed (no findings at info level)"
        fi
    else
        fail "Not enough community templates pulled ($YAML_COUNT). Check cent config."
    fi
fi

# ===========================================================
# TEST 10: New templates only (-nt flag)
# ===========================================================
if [[ "$SELECTED" == "all" || "$SELECTED" == "10" ]]; then
    OUTPUT="$RESULTS_DIR/test10_newtemplates.txt"
    run_test 10 "New Templates Only (-nt)" \
        "nuclei -u $TARGET -nt -stats -o $OUTPUT"

    live_run nuclei -u "$TARGET" \
        -nt \
        -stats \
        -timeout 10 \
        -rl 50 \
        -o "$OUTPUT"

    if [[ -s "$OUTPUT" ]]; then
        pass "New-templates scan produced results → $OUTPUT"
        head -5 "$OUTPUT"
    else
        echo "${YELLOW}[INFO]${NC} No new template findings (normal if templates were just updated)"
    fi
fi

# ===========================================================
# SUMMARY
# ===========================================================
echo ""
echo "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo "${CYAN}${BOLD}  TEST RESULTS SUMMARY${NC}"
echo "${CYAN}${BOLD}═══════════════════════════════════════════════════${NC}"
echo "Results directory: $RESULTS_DIR"
echo ""
for f in "$RESULTS_DIR"/test*.txt "$RESULTS_DIR"/test*.json; do
    if [[ -f "$f" ]]; then
        LINES=$(wc -l < "$f")
        SIZE=$(du -h "$f" | cut -f1)
        echo "  $(basename $f): ${LINES} lines (${SIZE})"
    fi
done
echo ""
echo "${GREEN}Done.${NC} Review results in: $RESULTS_DIR"
