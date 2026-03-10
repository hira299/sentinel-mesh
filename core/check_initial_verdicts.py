"""
check_initial_verdicts.py
=========================
Dry-run: passes all 105 benchmark cases through the Z3 verifier ONLY.
No LLM calls. No API keys needed. Fast.

Shows:
  - Which cases PASS initially (should be ~0 — all cases are intentionally broken)
  - Which cases FAIL correctly (good — verifier is detecting the vulnerability)
  - Summary counts and any suspicious patterns

Run from project root:
  python check_initial_verdicts.py
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier

# ── Config ────────────────────────────────────────────────────────────────────
BASE_DIR   = "benchmark/test_cases"
SHOW_ALL   = True   # set False to only show PASS cases (the suspicious ones)

# ANSI colors
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── Run ───────────────────────────────────────────────────────────────────────
folders = sorted([
    f for f in os.listdir(BASE_DIR)
    if os.path.isdir(os.path.join(BASE_DIR, f))
])

pass_cases        = []
fail_cases        = []
parser_error_cases = []

print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  SENTINEL-MESH — Initial Z3 Verdict Audit ({len(folders)} cases){RESET}")
print(f"{BOLD}{'='*70}{RESET}\n")

for idx, folder in enumerate(folders, 1):
    tf_file = os.path.join(BASE_DIR, folder, "main.tf")
    if not os.path.exists(tf_file):
        print(f"  {YELLOW}[SKIP]{RESET} {folder} — no main.tf found")
        continue

    data   = parse_hcl(tf_file)
    result = global_verifier(data)

    is_pass         = result.startswith("PASS")
    is_parser_error = "error" in data

    # Truncate long verdicts for display
    short_result = result[:90] + ("..." if len(result) > 90 else "")

    if is_parser_error:
        parser_error_cases.append((folder, result))
        print(f"  {YELLOW}[{idx:03d}] PARSER ERROR{RESET}  {folder}")
        print(f"         {YELLOW}↳ {short_result}{RESET}")
    elif is_pass:
        pass_cases.append((folder, result))
        # Always show PASS cases — these are suspicious
        print(f"  {GREEN}[{idx:03d}] PASS{RESET}          {BOLD}{folder}{RESET}")
        print(f"         {GREEN}↳ {short_result}{RESET}")
    else:
        fail_cases.append((folder, result))
        if SHOW_ALL:
            print(f"  {RED}[{idx:03d}] FAIL{RESET}          {folder}")
            print(f"         {RED}↳ {short_result}{RESET}")

# ── Summary ───────────────────────────────────────────────────────────────────
total = len(folders)
print(f"\n{BOLD}{'='*70}{RESET}")
print(f"{BOLD}  SUMMARY{RESET}")
print(f"{'='*70}")
print(f"  Total cases:      {total}")
print(f"  {RED}FAIL (correct): {len(fail_cases)}{RESET}   ← verifier caught the vulnerability")
print(f"  {GREEN}PASS (review):  {len(pass_cases)}{RESET}   ← these should be 0 ideally")
print(f"  {YELLOW}Parser errors:  {len(parser_error_cases)}{RESET}")
print(f"{'='*70}")

if pass_cases:
    print(f"\n{BOLD}{YELLOW}⚠️  CASES THAT PASS INITIALLY (need investigation):{RESET}")
    for folder, result in pass_cases:
        print(f"  • {folder}")
        print(f"    {result[:100]}")

if parser_error_cases:
    print(f"\n{BOLD}{YELLOW}⚠️  PARSER ERRORS:{RESET}")
    for folder, result in parser_error_cases:
        print(f"  • {folder}: {result[:80]}")

detection_rate = (len(fail_cases) / max(1, total - len(parser_error_cases))) * 100
print(f"\n{BOLD}  Vulnerability Detection Rate: {detection_rate:.1f}%{RESET}")
print(f"  (For your paper: Sentinel-Mesh detected {len(fail_cases)}/{total} intentional misconfigurations)")
print(f"{BOLD}{'='*70}{RESET}\n")