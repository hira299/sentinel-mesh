"""
external_wild_runner.py - Sentinel-Mesh External Wild IaC Benchmark Runner
===========================================================================
Module Purpose
--------------
Executes the full Sentinel-Mesh formal-verification and neuro-remediation
closed-loop pipeline against externally sourced, real-world ("wild") Terraform
configurations located in benchmark/external_wild_cases/. This evaluation
operationalises the external validity condition: assessing whether the CPM
invariants and LLM synthesis pipeline generalise beyond the curated
CloudFix-Bench dataset to unsanitised, production-derived IaC artefacts.

Scan Protocol
-------------
All .tf files within benchmark/external_wild_cases/ are discovered
recursively. Each file is treated as an independent evaluation unit:

1. Phase 1 - Z3 boundary verification: parse_hcl + global_verifier.
2. Phase 2 - Closed-loop remediation (k_max=5, full witness feedback):
   run_sentinel_mesh() invoked with the full symbolic counterexample loop.
3. Phase 3 - Atomic CSV persistence to logs/research_data_wild_cases.csv.

Structural Differences from experiment_runner.py
-------------------------------------------------
- Scan target: benchmark/external_wild_cases/ (not benchmark/test_cases/).
- Case identifier: relative path from external_wild_cases/ root.
- All .tf files are enumerated; there is no requirement for a main.tf
  naming convention.
- Checkpoint resume is keyed on relative file path (case_id field).

References
----------
- CloudFix-Bench: 105-case IaC security remediation benchmark (this work).
- Bridgecrew/Checkov: Infrastructure-as-Code static analysis (2021).
"""

from __future__ import annotations

import sys
import os
import csv
import re
import time
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier
from core.orchestrator import run_sentinel_mesh
from core.llm_agent import inter_case_sleep, set_provider_lock

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

# ---------------------------------------------------------------------------
# Filesystem constants
# ---------------------------------------------------------------------------
WILD_CASES_DIR = "benchmark/external_wild_cases"
OUTPUT_CSV     = "logs/research_data_wild_cases.csv"

# Maps CLI provider identifier to a provider-scoped output path.
_PROVIDER_CSV_MAP: dict[str, str] = {
    "gemini":   "logs/research_data_wild_cases_gemini.csv",
    "groq":     "logs/research_data_wild_cases_groq.csv",
    "cerebras": "logs/research_data_wild_cases_cerebras.csv",
}

FIELDNAMES = [
    "timestamp",
    "case_id",
    "tf_file",
    "z3_initial",
    "llm_attempts",
    "hallucination",
    "z3_final",
    "retry_history",
    "result",
]


# ---------------------------------------------------------------------------
# Filesystem Utilities
# ---------------------------------------------------------------------------

def _discover_tf_files(base_dir: str) -> list[str]:
    """
    Recursively enumerates all .tf files within `base_dir`.

    Returns a sorted list of relative paths from the current working directory,
    enabling deterministic evaluation order across invocations.

    Parameters
    ----------
    base_dir : str
        Root directory to scan for Terraform configuration files.

    Returns
    -------
    list[str]
        Sorted list of relative .tf file paths. Empty if `base_dir` does not
        exist or contains no .tf files.
    """
    tf_files: list[str] = []
    if not os.path.isdir(base_dir):
        return tf_files
    for dirpath, _dirnames, filenames in os.walk(base_dir):
        for fname in filenames:
            if fname.endswith(".tf"):
                tf_files.append(os.path.join(dirpath, fname))
    return sorted(tf_files)


def _make_case_id(tf_path: str, base_dir: str) -> str:
    """
    Derives a stable case identifier from the .tf file path.

    Returns the path relative to `base_dir`, normalised with forward slashes
    for cross-platform CSV portability. Used as the checkpoint key.

    Parameters
    ----------
    tf_path : str
        Absolute or relative path to a .tf file.
    base_dir : str
        Root scan directory; prefix stripped from `tf_path`.

    Returns
    -------
    str
        Forward-slash normalised relative path string.
    """
    rel = os.path.relpath(tf_path, base_dir)
    return rel.replace(os.sep, "/")


# ---------------------------------------------------------------------------
# Checkpoint Resume
# ---------------------------------------------------------------------------

def _load_completed_cases(csv_path: str) -> set:
    """
    Deserialises the set of case_id values already persisted to `csv_path`.

    Enables idempotent re-invocation without data duplication across
    interrupted sessions.
    """
    if not os.path.exists(csv_path):
        return set()
    completed: set = set()
    try:
        with open(csv_path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if row.get("case_id"):
                    completed.add(row["case_id"])
    except Exception:
        pass
    return completed


def _resolve_csv_path(provider: str | None) -> str:
    """
    Maps the --provider identifier to a provider-scoped output path.

    Falls back to the canonical wild-cases path for rotation mode.
    """
    return _PROVIDER_CSV_MAP.get(provider, OUTPUT_CSV) if provider else OUTPUT_CSV


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """
    Defines the CLI surface for the External Wild IaC Benchmark Runner.

    --provider restricts all LLM synthesis calls to a single provider,
    eliminating cross-provider confounding in wild-case evaluation results.
    """
    parser = argparse.ArgumentParser(
        prog="external_wild_runner",
        description=(
            "Sentinel-Mesh External Wild IaC Benchmark Runner. "
            "Executes the full formal-verification and neuro-remediation "
            "pipeline against all .tf files in benchmark/external_wild_cases/. "
            "Results persisted to logs/research_data_wild_cases.csv."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Scan target: benchmark/external_wild_cases/ (recursive, all .tf files).\n"
            "Pipeline: identical to full Sentinel-Mesh (k_max=5, witness feedback).\n\n"
            "Provider to model mapping:\n"
            "  gemini    gemini-flash-latest\n"
            "  groq      llama-3.3-70b-versatile\n"
            "  cerebras  gpt-oss-120b\n\n"
            "Output:\n"
            "  (none)    logs/research_data_wild_cases.csv\n"
            "  gemini    logs/research_data_wild_cases_gemini.csv\n"
            "  groq      logs/research_data_wild_cases_groq.csv\n"
            "  cerebras  logs/research_data_wild_cases_cerebras.csv\n"
        ),
    )
    parser.add_argument(
        "--provider",
        choices=["gemini", "groq", "cerebras"],
        default=None,
        metavar="PROVIDER",
        help=(
            "Pin all LLM synthesis calls to a single provider. "
            "Valid: gemini, groq, cerebras. "
            "Omit for default rotation (Cerebras -> Gemini -> Groq)."
        ),
    )
    parser.add_argument(
        "--wild-dir",
        default=WILD_CASES_DIR,
        metavar="DIR",
        help=(
            "Override the wild cases scan directory. "
            f"Default: {WILD_CASES_DIR}"
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main Evaluation Loop
# ---------------------------------------------------------------------------

def run_external_wild(provider: str | None = None, wild_dir: str = WILD_CASES_DIR) -> None:
    """
    Entry point for a single External Wild IaC benchmark evaluation session.

    Scans all .tf files in `wild_dir`, applies the full Sentinel-Mesh pipeline
    (initial Z3 verdict + closed-loop LLM remediation with witness feedback),
    and persists per-file results to a provider-scoped CSV log.

    Parameters
    ----------
    provider : str | None
        When non-None, engages set_provider_lock before the scan loop,
        routing all get_remediation_patch calls to the specified provider.
    wild_dir : str
        Root directory to scan for external .tf fixtures.
    """
    os.makedirs("logs", exist_ok=True)

    if provider is not None:
        set_provider_lock(provider)

    csv_file        = _resolve_csv_path(provider)
    condition_label = provider.upper() if provider else "ROTATION (Cerebras->Gemini->Groq)"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  EXTERNAL WILD IaC BENCHMARK - Sentinel-Mesh{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{CYAN}[CONFIG] Scan target            : {wild_dir}/{RESET}")
    print(f"{CYAN}[CONFIG] LLM provider           : {condition_label}{RESET}")
    print(f"{CYAN}[CONFIG] Pipeline               : Full Sentinel-Mesh (k_max=5, witness feedback){RESET}")
    print(f"{CYAN}[CONFIG] Judge                  : global_verifier (Z3, condition-blind){RESET}")
    print(f"{CYAN}[CONFIG] Output CSV             : {csv_file}{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    # Validate scan directory existence.
    if not os.path.isdir(wild_dir):
        print(f"{RED}[ERROR] Wild cases directory not found: {wild_dir}{RESET}")
        print(f"{YELLOW}[INFO] Create the directory and populate it with .tf files before running.{RESET}")
        print(f"{YELLOW}       mkdir -p {wild_dir}{RESET}")
        sys.exit(1)

    # Discover all .tf files within the wild cases directory.
    all_tf_files = _discover_tf_files(wild_dir)
    total        = len(all_tf_files)

    if total == 0:
        print(f"{YELLOW}[WARN] No .tf files found in {wild_dir}. Exiting.{RESET}")
        return

    print(f"{CYAN}[INGESTION] Discovered {total} .tf files in {wild_dir}/{RESET}")

    # Checkpoint resume keyed on relative path (case_id).
    completed = _load_completed_cases(csv_file)
    pending   = [f for f in all_tf_files if _make_case_id(f, wild_dir) not in completed]

    if completed:
        print(f"{YELLOW}[RESUME] {len(completed)} files already persisted - "
              f"resuming from file {len(completed)+1}/{total}{RESET}")
    else:
        print(f"{BOLD}{CYAN}[START] Initiating wild-case evaluation over {total} files{RESET}")

    if not pending:
        print(f"{GREEN}[DONE] All {total} files already completed.{RESET}")
        return

    # Open CSV in append mode; emit header only on file creation.
    file_exists = os.path.exists(csv_file) and os.path.getsize(csv_file) > 0
    csv_handle  = open(csv_file, mode="a", newline="", encoding="utf-8")
    writer      = csv.DictWriter(csv_handle, fieldnames=FIELDNAMES)
    if not file_exists:
        writer.writeheader()

    pass_count = fixed_count = hallucination_count = 0
    parse_error_count = 0
    all_attempts: list[int] = []
    start_time = time.time()

    try:
        for local_idx, tf_path in enumerate(pending, 1):
            global_idx = len(completed) + local_idx
            case_id    = _make_case_id(tf_path, wild_dir)
            tf_name    = os.path.basename(tf_path)

            # Rolling ETA estimate.
            elapsed   = time.time() - start_time
            rate      = local_idx / elapsed if elapsed > 0 else 0.1
            remaining = len(pending) - local_idx
            eta_secs  = int(remaining / rate) if rate > 0 else 0
            eta_str   = f"{eta_secs//60}m{eta_secs%60:02d}s"

            print(f"\n{BOLD}{'='*62}{RESET}")
            print(f"{BOLD}[{global_idx}/{total}]{RESET}  {CYAN}{case_id}{RESET}  "
                  f"{YELLOW}(ETA ~{eta_str}){RESET}")
            print(f"{CYAN}[TARGET]{RESET}   {tf_path}")
            print(f"{CYAN}[TIMESTAMP]{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            # Phase 1: Initial Z3 verdict (pre-remediation).
            print(f"\n{BOLD}[PHASE 1] Initial Z3-SMT Verification{RESET}")
            try:
                data       = parse_hcl(tf_path)
                z3_initial = global_verifier(data)
            except Exception as exc:
                parse_error_count += 1
                err_msg = str(exc)[:200]
                print(f"      {RED}[PARSE ERROR] HCL2/Z3 failure on wild fixture: {err_msg}{RESET}")
                writer.writerow({
                    "timestamp":     datetime.now().strftime("%H:%M:%S"),
                    "case_id":       case_id,
                    "tf_file":       tf_name,
                    "z3_initial":    f"PARSE_ERROR: {err_msg}",
                    "llm_attempts":  0,
                    "hallucination": True,
                    "z3_final":      "N/A",
                    "retry_history": "N/A",
                    "result":        "PARSE_ERROR",
                })
                csv_handle.flush()
                inter_case_sleep(global_idx)
                continue

            # Phase 2: Full Sentinel-Mesh closed-loop remediation.
            print(f"\n{BOLD}[PHASE 2] Full Sentinel-Mesh Closed-Loop Remediation{RESET}")
            try:
                outcome = run_sentinel_mesh(tf_path)
            except Exception as exc:
                err_msg = str(exc)[:200]
                print(f"      {RED}[PIPELINE ERROR] run_sentinel_mesh raised: {err_msg}{RESET}")
                writer.writerow({
                    "timestamp":     datetime.now().strftime("%H:%M:%S"),
                    "case_id":       case_id,
                    "tf_file":       tf_name,
                    "z3_initial":    z3_initial,
                    "llm_attempts":  0,
                    "hallucination": True,
                    "z3_final":      f"PIPELINE_ERROR: {err_msg}",
                    "retry_history": "N/A",
                    "result":        "PIPELINE_ERROR",
                })
                csv_handle.flush()
                inter_case_sleep(global_idx)
                continue

            result        = outcome["result"]
            attempts      = outcome["attempts"]
            retry_hist    = outcome["retry_history"]
            final_verdict = outcome["final_verdict"]
            hallucination = result == "HALLUCINATION"
            retry_str     = " | ".join(retry_hist) if retry_hist else "N/A"

            # Phase 3: Atomic CSV persistence.
            writer.writerow({
                "timestamp":     datetime.now().strftime("%H:%M:%S"),
                "case_id":       case_id,
                "tf_file":       tf_name,
                "z3_initial":    z3_initial,
                "llm_attempts":  attempts,
                "hallucination": hallucination,
                "z3_final":      final_verdict,
                "retry_history": retry_str,
                "result":        result,
            })
            csv_handle.flush()

            # Console per-case summary.
            if result == "PASS":
                pass_count += 1
                print(f"      {GREEN}PASS{RESET} - no violation detected")
            elif result == "FIXED":
                fixed_count += 1
                all_attempts.append(attempts)
                print(f"      {GREEN}FIXED{RESET} - {MAGENTA}{attempts}{RESET} attempt(s)")
            else:
                hallucination_count += 1
                all_attempts.append(attempts)
                print(f"      {RED}HALLUCINATION{RESET} - failed after {attempts} attempt(s)")

            inter_case_sleep(global_idx)

    finally:
        csv_handle.close()

    # Session summary.
    avg           = (sum(all_attempts) / len(all_attempts)) if all_attempts else 0.0
    total_elapsed = int(time.time() - start_time)
    total_run     = len(pending)

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}EXTERNAL WILD IaC BENCHMARK - SESSION COMPLETE{RESET}")
    print(f"{BOLD}Scan dir  : {wild_dir}  |  Provider: {condition_label}{RESET}")
    print(f"{'='*65}")
    print(f"Files evaluated this session     : {total_run}")
    print(f"Total elapsed                    : {total_elapsed//60}m{total_elapsed%60:02d}s")
    print(f"{GREEN}Naturally Secure (PASS)          : {pass_count}{RESET}")
    print(f"{GREEN}Fixed (Z3 verified)              : {fixed_count}{RESET}")
    print(f"{RED}Persistent Hallucination         : {hallucination_count}{RESET}")
    print(f"{RED}Parse / Pipeline Errors          : {parse_error_count}{RESET}")
    print(f"{YELLOW}Avg LLM Attempts (fixed only)    : {avg:.2f}{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"\n{CYAN}Full dataset: {csv_file}{RESET}")
    print(f"{CYAN}Re-invoke to resume from checkpoint if interrupted.{RESET}\n")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = _parse_args()
    run_external_wild(provider=args.provider, wild_dir=args.wild_dir)
