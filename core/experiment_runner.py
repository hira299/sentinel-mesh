"""
experiment_runner.py — Sentinel-Mesh Batch Benchmark Runner
============================================================
CLI Interface
-------------
  --provider {gemini,groq,cerebras}
      Restricts all LLM synthesis calls to the specified provider by engaging
      a singleton dispatch lock in llm_agent before the benchmark loop begins.
      Eliminates cross-provider confounding; results are written to a
      provider-scoped CSV (e.g., logs/research_data_gemini.csv) so that
      conditions remain independently reproducible.

      Omitting --provider restores the default rotation schedule
      (Cerebras → Gemini → Groq per attempt) and writes to the canonical
      logs/research_data_v100.csv.

Checkpoint Resume
-----------------
  Reads the target CSV on startup; cases whose case_id already appears are
  skipped, allowing interrupted runs to continue without data duplication.

Rate-Limit Mitigation
---------------------
  - Intra-attempt cooldown tracking persists across all cases in one session.
  - Inter-case sleep with jitter + checkpoint pauses every 10 cases.
"""

from __future__ import annotations  # defer annotation eval — supports str | None on Python < 3.10

import sys
import os
import csv
import time
import argparse
from datetime import datetime

# Maps CLI provider identifier → canonical CSV filename suffix.
# Extending this dict is the only change required to register a new condition.
_PROVIDER_CSV_MAP: dict[str, str] = {
    "gemini":   "logs/research_data_gemini.csv",
    "groq":     "logs/research_data_groq.csv",
    "cerebras": "logs/research_data_cerebras.csv",
}
_DEFAULT_CSV = "logs/research_data_v100.csv"

CYAN    = "\033[96m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
RED     = "\033[91m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import run_sentinel_mesh
from core.llm_agent import inter_case_sleep, set_provider_lock
from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier


# CSV_FILE is resolved at runtime from --provider; see _resolve_csv_path().
CSV_FILE: str = _DEFAULT_CSV
BASE_DIR  = "benchmark/test_cases"
FIELDNAMES = [
    "timestamp", "case_id", "resource",
    "z3_initial", "llm_attempts",
    "hallucination", "z3_final", "retry_history"
]


def _resolve_csv_path(provider: str | None) -> str:
    """
    Maps the --provider identifier to a provider-scoped output path.

    Using a separate file per provider prevents experimental conditions from
    sharing a log, which would confound provider-level comparative analysis.
    Falls back to the canonical v100 path for rotation-mode (provider=None).
    """
    return _PROVIDER_CSV_MAP.get(provider, _DEFAULT_CSV) if provider else _DEFAULT_CSV


def _load_completed_cases(csv_path: str) -> set:
    """
    Scans `csv_path` and returns the set of case_ids already persisted.

    Used to implement checkpoint resume: cases present in the log are excluded
    from `pending`, ensuring idempotent re-invocation without data duplication.
    """
    if not os.path.exists(csv_path):
        return set()
    completed = set()
    try:
        with open(csv_path, newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row.get("case_id"):
                    completed.add(row["case_id"])
    except Exception:
        pass
    return completed


def _parse_args() -> argparse.Namespace:
    """
    Defines the CLI surface for the benchmark runner.

    --provider partitions the experimental condition at the process boundary:
    the runner engages a singleton dispatch lock before the first benchmark
    case, ensuring every LLM synthesis call within this session is routed
    exclusively to the specified provider/model version pair.
    """
    parser = argparse.ArgumentParser(
        prog="experiment_runner",
        description=(
            "Sentinel-Mesh Batch Benchmark Runner. "
            "Executes the formal-verification + neuro-remediation loop across "
            "all benchmark cases and persists results to a CSV log."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Provider → Model mapping (pinned for reproducibility):\n"
            "  gemini    gemini-flash-latest / gemini-robotics-er-1.5-preview\n"
            "  groq      llama-3.3-70b-versatile\n"
            "  cerebras  gpt-oss-120b\n\n"
            "Output CSV is provider-scoped when --provider is supplied:\n"
            "  (none)    logs/research_data_v100.csv   [rotation mode]\n"
            "  gemini    logs/research_data_gemini.csv\n"
            "  groq      logs/research_data_groq.csv\n"
            "  cerebras  logs/research_data_cerebras.csv\n"
        ),
    )
    parser.add_argument(
        "--provider",
        choices=["gemini", "groq", "cerebras"],
        default=None,
        metavar="PROVIDER",
        help=(
            "Pin all LLM synthesis calls to a single provider. "
            "Valid values: gemini, groq, cerebras. "
            "Omit for default rotation (Cerebras → Gemini → Groq per attempt)."
        ),
    )
    return parser.parse_args()


def run_experiment(provider: str | None = None) -> None:
    """
    Entry point for a single benchmark session.

    Parameters
    ----------
    provider : str | None
        When non-None, engages `set_provider_lock` before the loop, restricting
        all `get_remediation_patch` calls within this session to the specified
        provider. The CSV output path is simultaneously scoped to prevent
        cross-condition data interleaving.
    """
    os.makedirs("logs", exist_ok=True)

    # ── Resolve provider lock and output path ─────────────────────────────────
    # Lock must be engaged before any orchestrator call; fail-fast if the
    # provider's API key is absent or the client failed to initialise.
    if provider is not None:
        set_provider_lock(provider)

    csv_file = _resolve_csv_path(provider)

    # ── Emit run header with experimental condition metadata ──────────────────
    condition_label = provider.upper() if provider else "ROTATION (Cerebras→Gemini→Groq)"
    print(f"{BOLD}{CYAN}[CONFIG] Provider condition : {condition_label}{RESET}")
    print(f"{BOLD}{CYAN}[CONFIG] Output CSV         : {csv_file}{RESET}")

    all_folders = sorted([
        f for f in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, f))
        and os.path.exists(os.path.join(BASE_DIR, f, "main.tf"))
    ])
    total = len(all_folders)

    # ── Checkpoint resume ─────────────────────────────────────────────────────
    # Reads the target CSV (provider-scoped) to identify already-persisted cases;
    # ensures re-invocation is idempotent within a given experimental condition.
    completed = _load_completed_cases(csv_file)
    pending   = [f for f in all_folders if f not in completed]

    if completed:
        print(f"{YELLOW}[RESUME] {len(completed)} cases already done — "
              f"resuming from case {len(completed)+1}/{total}{RESET}")
    else:
        print(f"{BOLD}{CYAN}[START] Sentinel-Mesh Benchmark: {total} cases{RESET}")

    if not pending:
        print(f"{GREEN}[DONE] All {total} cases already completed for condition: {condition_label}{RESET}")
        return

    # ── Open CSV in append mode (write header only if new file) ──────────────
    file_exists = os.path.exists(csv_file) and os.path.getsize(csv_file) > 0
    csv_handle  = open(csv_file, mode='a', newline='', encoding='utf-8')
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

            # ── ETA estimate (rolling rate over elapsed wall time) ────────────
            elapsed   = time.time() - start_time
            rate      = local_idx / elapsed if elapsed > 0 else 0.1
            remaining = len(pending) - local_idx
            eta_secs  = int(remaining / rate) if rate > 0 else 0
            eta_str   = f"{eta_secs//60}m{eta_secs%60:02d}s"

            print(f"\n{BOLD}[{global_idx}/{total}]{RESET} {CYAN}{folder}{RESET}  "
                  f"{YELLOW}(ETA ~{eta_str}){RESET}")

            # ── Phase 1: initial Z3 verdict before LLM remediation ────────────
            data       = parse_hcl(tf_file)
            z3_initial = global_verifier(data)

            # ── Phase 2: closed-loop neuro-remediation (LLM + Z3 retry) ───────
            outcome       = run_sentinel_mesh(tf_file)
            result        = outcome["result"]
            attempts      = outcome["attempts"]
            retry_hist    = outcome["retry_history"]
            final_verdict = outcome["final_verdict"]

            resource_prefix = folder.split("_")[0]
            hallucination   = result == "HALLUCINATION"
            retry_str       = " | ".join(retry_hist) if retry_hist else "N/A"

            # ── Persist row; flush immediately to survive interruption ─────────
            writer.writerow({
                "timestamp":     datetime.now().strftime("%H:%M:%S"),
                "case_id":       folder,
                "resource":      resource_prefix,
                "z3_initial":    z3_initial,
                "llm_attempts":  attempts,
                "hallucination": hallucination,
                "z3_final":      final_verdict,
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

            # ── Rate-limit mitigation: smart inter-case sleep with jitter ─────
            inter_case_sleep(global_idx)

    finally:
        csv_handle.close()

    # ── Session summary ───────────────────────────────────────────────────────
    avg           = (sum(all_attempts) / len(all_attempts)) if all_attempts else 0
    total_elapsed = int(time.time() - start_time)

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}BENCHMARK COMPLETE — {csv_file}{RESET}")
    print(f"{BOLD}Condition: {condition_label}{RESET}")
    print(f"{'='*60}")
    print(f"Total cases run this session:  {len(pending)}")
    print(f"Total elapsed:                 {total_elapsed//60}m{total_elapsed%60:02d}s")
    print(f"{GREEN}Naturally Secure:              {pass_count}{RESET}")
    print(f"{GREEN}Successfully Fixed:            {fixed_count}{RESET}")
    print(f"{RED}Persistent Hallucination:      {hallucination_count}{RESET}")
    print(f"{YELLOW}Avg LLM Attempts (fixed only): {avg:.2f}{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"\n{CYAN}Full dataset: {csv_file}{RESET}")
    print(f"{CYAN}Run again to resume from where this stopped.{RESET}")


if __name__ == "__main__":
    args = _parse_args()
    run_experiment(provider=args.provider)