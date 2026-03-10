"""
experiment_runner.py — Sentinel-Mesh Batch Benchmark Runner
============================================================
Features:
  - Checkpoint resume: if the run is interrupted, restart and it picks up
    from where it left off (reads existing CSV to find completed cases).
  - Smart inter-case sleep via llm_agent.inter_case_sleep()
  - Provider cooldown tracking persists across all cases in one run
  - Progress bar with ETA
  - Final summary table
"""

import sys
import os
import csv
import time
from datetime import datetime

CYAN    = "\033[96m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import run_sentinel_mesh
from core.llm_agent import inter_case_sleep
from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier


CSV_FILE  = "logs/research_data_v100.csv"
BASE_DIR  = "benchmark/test_cases"
FIELDNAMES = [
    "timestamp", "case_id", "resource",
    "z3_initial", "llm_attempts",
    "hallucination", "z3_final", "retry_history"
]


def _load_completed_cases() -> set:
    """Read CSV and return set of case_ids already completed."""
    if not os.path.exists(CSV_FILE):
        return set()
    completed = set()
    try:
        with open(CSV_FILE, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("case_id"):
                    completed.add(row["case_id"])
    except Exception:
        pass
    return completed


def run_experiment():
    os.makedirs("logs", exist_ok=True)

    all_folders = sorted([
        f for f in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, f))
        and os.path.exists(os.path.join(BASE_DIR, f, "main.tf"))
    ])
    total = len(all_folders)

    # ── Checkpoint resume ─────────────────────────────────────────────────────
    completed = _load_completed_cases()
    pending   = [f for f in all_folders if f not in completed]

    if completed:
        print(f"{YELLOW}[RESUME] {len(completed)} cases already done — resuming from case {len(completed)+1}/{total}{RESET}")
    else:
        print(f"{BOLD}{CYAN}[START] Sentinel-Mesh Benchmark: {total} cases{RESET}")

    if not pending:
        print(f"{GREEN}[DONE] All {total} cases already completed!{RESET}")
        return

    # ── Open CSV in append mode (write header only if new file) ──────────────
    file_exists = os.path.exists(CSV_FILE) and os.path.getsize(CSV_FILE) > 0
    csv_handle  = open(CSV_FILE, mode='a', newline='', encoding='utf-8')
    writer      = csv.DictWriter(csv_handle, fieldnames=FIELDNAMES)
    if not file_exists:
        writer.writeheader()

    pass_count = hallucination_count = fixed_count = 0
    all_attempts = []
    start_time = time.time()

    try:
        for local_idx, folder in enumerate(pending, 1):
            global_idx = len(completed) + local_idx
            tf_file    = os.path.join(BASE_DIR, folder, "main.tf")

            # ETA estimate
            elapsed     = time.time() - start_time
            rate        = local_idx / elapsed if elapsed > 0 else 0.1
            remaining   = len(pending) - local_idx
            eta_secs    = int(remaining / rate) if rate > 0 else 0
            eta_str     = f"{eta_secs//60}m{eta_secs%60:02d}s"

            print(f"\n{BOLD}[{global_idx}/{total}]{RESET} {CYAN}{folder}{RESET}  "
                  f"{YELLOW}(ETA ~{eta_str}){RESET}")

            # ── Get initial Z3 verdict ────────────────────────────────────────
            data       = parse_hcl(tf_file)
            z3_initial = global_verifier(data)

            # ── Run orchestrator (LLM + Z3 loop) ─────────────────────────────
            outcome      = run_sentinel_mesh(tf_file)
            result       = outcome["result"]
            attempts     = outcome["attempts"]
            retry_hist   = outcome["retry_history"]
            final_verdict = outcome["final_verdict"]

            resource_prefix = folder.split("_")[0]
            hallucination   = result == "HALLUCINATION"
            retry_str       = " | ".join(retry_hist) if retry_hist else "N/A"

            # ── Write row ─────────────────────────────────────────────────────
            writer.writerow({
                "timestamp":    datetime.now().strftime("%H:%M:%S"),
                "case_id":      folder,
                "resource":     resource_prefix,
                "z3_initial":   z3_initial,
                "llm_attempts": attempts,
                "hallucination": hallucination,
                "z3_final":     final_verdict,
                "retry_history": retry_str,
            })
            csv_handle.flush()

            # ── Console summary ───────────────────────────────────────────────
            if result == "PASS":
                pass_count += 1
                print(f"      {GREEN}PASS{RESET} — no violation")
            elif result == "FIXED":
                fixed_count += 1
                all_attempts.append(attempts)
                print(f"      {GREEN}FIXED{RESET} — {MAGENTA}{attempts}{RESET} attempt(s)")
            else:
                hallucination_count += 1
                all_attempts.append(attempts)
                print(f"      {RED}HALLUCINATION{RESET} — failed after {attempts} attempt(s)")

            # ── Smart inter-case sleep ────────────────────────────────────────
            inter_case_sleep(global_idx)

    finally:
        csv_handle.close()

    # ── Final summary ─────────────────────────────────────────────────────────
    avg = (sum(all_attempts) / len(all_attempts)) if all_attempts else 0
    total_elapsed = int(time.time() - start_time)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}BENCHMARK COMPLETE — {CSV_FILE}{RESET}")
    print(f"{'='*60}")
    print(f"Total cases run this session:  {len(pending)}")
    print(f"Total elapsed:                 {total_elapsed//60}m{total_elapsed%60:02d}s")
    print(f"{GREEN}Naturally Secure:              {pass_count}{RESET}")
    print(f"{GREEN}Successfully Fixed:            {fixed_count}{RESET}")
    print(f"{RED}Persistent Hallucination:      {hallucination_count}{RESET}")
    print(f"{YELLOW}Avg LLM Attempts (fixed only): {avg:.2f}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"\n{CYAN}Full dataset: {CSV_FILE}{RESET}")
    print(f"{CYAN}Run again to resume from where this stopped.{RESET}")


if __name__ == "__main__":
    run_experiment()