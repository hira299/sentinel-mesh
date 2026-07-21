"""
ablation_no_witness_runner.py - Sentinel-Mesh Ablation Condition B
===================================================================
Module Purpose
--------------
Implements the "No-Witness" ablation condition for comparative evaluation
against the full Sentinel-Mesh pipeline (CloudFix-Bench, N=105). The Z3
symbolic counterexample witness model is suppressed from LLM retry prompts,
isolating the marginal contribution of witness-guided feedback to the overall
remediation rate.

Ablation Variable (Condition B)
--------------------------------
Full Sentinel-Mesh (Condition A): retry prompt embeds the Z3 witness
  model (e.g., {Z=0, E=0, S=1}) as structured symbolic context.
No-Witness Ablation (Condition B): retry prompt substitutes a generic
  rejection string conveying only binary pass/fail status.

Evaluation Protocol (per case)
--------------------------------
1. Phase 1 - Initial Z3 verdict: parse_hcl + global_verifier.
2. Phase 2 - Closed-loop remediation (k_max=5):
   a. Construct retry prompt with generic rejection string (witness suppressed).
   b. Invoke LLM synthesis (get_remediation_patch).
   c. Submit synthesized patch to global_verifier (Z3, condition-blind).
   d. On PASS: record FIXED and break.
   e. On FAIL: retain generic rejection string for next iteration.
3. Phase 3 - Atomic CSV persistence after each case.

Isolation Guarantees
--------------------
- Z3 witness model is never passed to the LLM in any retry iteration.
- Z3 judge is condition-blind: receives only patched HCL.
- Provider lock and checkpoint-resume semantics are structurally
  identical to experiment_runner.py for experimental comparability.

References
----------
- de Moura and Bjorner, Z3: An Efficient SMT Solver, TACAS 2008.
- CloudFix-Bench: 105-case IaC security remediation benchmark (this work).
"""

from __future__ import annotations

import sys
import os
import csv
import re
import time
import tempfile
import argparse
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier
from core.llm_agent import get_remediation_patch, inter_case_sleep, set_provider_lock

GREEN   = "\033[92m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

BASE_DIR    = "benchmark/test_cases"
PATCHES_DIR = "logs/patches"
K_MAX       = 5

# Generic rejection string: conveys binary failure status only.
# Suppresses symbolic counterexample payload to establish the No-Witness baseline.
_GENERIC_REJECTION = (
    "The proposed Terraform patch failed security verification constraints. "
    "Please rewrite the configuration to ensure compliance."
)

# Compiled regex for HCL fence extraction - mirrors CODE-03 in orchestrator.py.
_HCL_FENCE_RE = re.compile(
    r"```(?:hcl|terraform)?\s*(.*?)\s*```",
    re.DOTALL | re.IGNORECASE,
)

FIELDNAMES = [
    "timestamp", "case_id", "resource",
    "z3_initial", "llm_attempts",
    "hallucination", "z3_final", "retry_history",
]

# Maps CLI provider identifier to a provider-scoped output path.
_PROVIDER_CSV_MAP: dict[str, str] = {
    "gemini":   "logs/research_data_no_witness_gemini.csv",
    "groq":     "logs/research_data_no_witness_groq.csv",
    "cerebras": "logs/research_data_no_witness_cerebras.csv",
}
_DEFAULT_CSV = "logs/research_data_no_witness.csv"


def _extract_clean_hcl(raw_output: str) -> str:
    """
    Extracts the HCL payload from an LLM text response via regular expression
    matching against the canonical fenced code block pattern.

    Returns the captured interior of the first matching fence, or the full
    string stripped of whitespace when no fence delimiter is present.
    """
    match = _HCL_FENCE_RE.search(raw_output)
    if match:
        return match.group(1).strip()
    return raw_output.strip()


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

    Falls back to the canonical no-witness path for rotation mode (provider=None).
    """
    return _PROVIDER_CSV_MAP.get(provider, _DEFAULT_CSV) if provider else _DEFAULT_CSV


def _parse_args() -> argparse.Namespace:
    """
    Defines the CLI surface for the No-Witness ablation runner.

    --provider restricts all LLM synthesis calls to a single provider,
    eliminating cross-provider confounding in the ablation results.
    """
    parser = argparse.ArgumentParser(
        prog="ablation_no_witness_runner",
        description=(
            "Sentinel-Mesh Ablation Condition B: No-Witness Feedback. "
            "Suppresses Z3 symbolic counterexample witnesses from LLM retry "
            "prompts. Results persisted to logs/research_data_no_witness.csv."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ablation variable: Z3 witness suppressed from retry prompt.\n"
            "Retry budget k_max=5 (identical to full Sentinel-Mesh pipeline).\n\n"
            "Provider to model mapping:\n"
            "  gemini    gemini-flash-latest\n"
            "  groq      llama-3.3-70b-versatile\n"
            "  cerebras  gpt-oss-120b\n\n"
            "Output:\n"
            "  (none)    logs/research_data_no_witness.csv\n"
            "  gemini    logs/research_data_no_witness_gemini.csv\n"
            "  groq      logs/research_data_no_witness_groq.csv\n"
            "  cerebras  logs/research_data_no_witness_cerebras.csv\n"
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
    return parser.parse_args()


def _run_no_witness_case(tf_file_path: str, case_name: str) -> dict:
    """
    Executes the No-Witness ablation remediation loop for a single benchmark case.

    Structural parity with run_sentinel_mesh() in orchestrator.py is preserved
    except for retry prompt construction: the Z3 witness model is suppressed
    and replaced by _GENERIC_REJECTION on every iteration.

    Parameters
    ----------
    tf_file_path : str
        Path to the target Terraform fixture (main.tf).
    case_name : str
        Directory basename used as the benchmark case identifier.

    Returns
    -------
    dict
        Keys: result, attempts, retry_history, final_verdict, z3_initial.
    """
    print(f"\n{BOLD}{'='*62}{RESET}")
    print(f"{CYAN}[ABLATION-B]{RESET} No-Witness scan: {BOLD}{case_name}{RESET}")
    print(f"{CYAN}[TARGET]{RESET}      {tf_file_path}")
    print(f"{CYAN}[TIMESTAMP]{RESET}   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*62}{RESET}")

    # Phase 1: Initial symbolic boundary verification.
    print(f"\n{BOLD}[PHASE 1] Initial Z3-SMT Verification{RESET}")
    data       = parse_hcl(tf_file_path)
    z3_initial = global_verifier(data)

    if "PASS" in z3_initial:
        print(f"{GREEN}[PASS] Configuration satisfies all Cloud Perimeter invariants.{RESET}")
        return {
            "result":        "PASS",
            "attempts":      0,
            "retry_history": [],
            "final_verdict": z3_initial,
            "z3_initial":    z3_initial,
        }

    print(f"{RED}[VIOLATION] {z3_initial}{RESET}")

    # Phase 2: Closed-loop remediation with witness suppression.
    print(f"\n{BOLD}[PHASE 2] No-Witness Closed-Loop Remediation (k_max={K_MAX}){RESET}")

    with open(tf_file_path, "r", encoding="utf-8") as fh:
        original_hcl = fh.read()

    retry_history: list[str] = []
    attempt = 0

    while attempt < K_MAX:
        attempt += 1
        print(f"\n{MAGENTA}[ATTEMPT {attempt}/{K_MAX}]{RESET} Invoking LLM synthesis - witness suppressed.")
        print(f"      {YELLOW}Rejection context (generic): {_GENERIC_REJECTION[:80]}...{RESET}")

        # Symbolic counterexample payload suppressed: pass generic rejection string.
        raw_patch   = get_remediation_patch(original_hcl, _GENERIC_REJECTION, attempt)
        clean_patch = _extract_clean_hcl(raw_patch)

        if clean_patch.startswith("# ERROR:") or not clean_patch.strip():
            print(f"      {RED}[LLM] Synthesis failed - no valid patch generated.{RESET}")
            retry_history.append("LLM_SYNTHESIS_FAILURE")
            continue

        print(f"      {CYAN}Submitting synthesized patch to global_verifier (Z3, condition-blind).{RESET}")

        temp_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                suffix=".tf", mode="w", delete=False, encoding="utf-8"
            ) as tmp:
                tmp.write(clean_patch)
                temp_path = tmp.name

            patch_data = parse_hcl(temp_path)

            if "error" in patch_data:
                print(f"      {RED}[PARSE ERROR] HCL2 parse failure: {patch_data['error']}{RESET}")
                retry_history.append(f"HCL_PARSE_ERROR: {patch_data['error'][:120]}")
                continue

            z3_result = global_verifier(patch_data)

        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)

        retry_history.append(z3_result)

        if "PASS" in z3_result:
            print(f"{GREEN}[PASS] Attempt {attempt}: Z3 formally verified - patch is secure.{RESET}")
            return {
                "result":        "FIXED",
                "attempts":      attempt,
                "retry_history": retry_history,
                "final_verdict": z3_result,
                "z3_initial":    z3_initial,
            }

        # Witness suppression: discard z3_result and reuse generic rejection on next iteration.
        print(f"      {RED}[FAIL] Attempt {attempt}: Z3 rejected. Witness suppressed for retry.{RESET}")

    print(f"\n{RED}[CRITICAL] Persistent hallucination after {K_MAX} attempts: {case_name}{RESET}")
    return {
        "result":        "HALLUCINATION",
        "attempts":      attempt,
        "retry_history": retry_history,
        "final_verdict": retry_history[-1] if retry_history else "NO_PATCH",
        "z3_initial":    z3_initial,
    }


def run_no_witness_ablation(provider: str | None = None) -> None:
    """
    Entry point for a single No-Witness ablation evaluation session.

    Parameters
    ----------
    provider : str | None
        When non-None, engages set_provider_lock before the benchmark loop,
        routing all get_remediation_patch calls to the specified provider.
    """
    os.makedirs("logs",      exist_ok=True)
    os.makedirs(PATCHES_DIR, exist_ok=True)

    if provider is not None:
        set_provider_lock(provider)

    csv_file        = _resolve_csv_path(provider)
    condition_label = provider.upper() if provider else "ROTATION (Cerebras->Gemini->Groq)"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  ABLATION CONDITION B - NO-WITNESS FEEDBACK - Sentinel-Mesh{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{CYAN}[CONFIG] Ablation variable      : Z3 witness suppressed from retry prompt{RESET}")
    print(f"{CYAN}[CONFIG] LLM provider           : {condition_label}{RESET}")
    print(f"{CYAN}[CONFIG] Retry budget (k_max)   : {K_MAX}{RESET}")
    print(f"{CYAN}[CONFIG] Judge                  : global_verifier (Z3, condition-blind){RESET}")
    print(f"{CYAN}[CONFIG] Output CSV             : {csv_file}{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    all_folders = sorted([
        f for f in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, f))
        and os.path.exists(os.path.join(BASE_DIR, f, "main.tf"))
    ])
    total = len(all_folders)
    print(f"{CYAN}[INGESTION] Discovered {total} benchmark cases in {BASE_DIR}/{RESET}")

    completed = _load_completed_cases(csv_file)
    pending   = [f for f in all_folders if f not in completed]

    if completed:
        print(f"{YELLOW}[RESUME] {len(completed)} cases already persisted - "
              f"resuming from case {len(completed)+1}/{total}{RESET}")
    else:
        print(f"{BOLD}{CYAN}[START] Initiating No-Witness ablation over {total} cases{RESET}")

    if not pending:
        print(f"{GREEN}[DONE] All {total} cases already completed.{RESET}")
        return

    file_exists = os.path.exists(csv_file) and os.path.getsize(csv_file) > 0
    csv_handle  = open(csv_file, mode="a", newline="", encoding="utf-8")
    writer      = csv.DictWriter(csv_handle, fieldnames=FIELDNAMES)
    if not file_exists:
        writer.writeheader()

    pass_count = fixed_count = hallucination_count = 0
    all_attempts: list[int] = []
    start_time = time.time()

    try:
        for local_idx, folder in enumerate(pending, 1):
            global_idx = len(completed) + local_idx
            tf_file    = os.path.join(BASE_DIR, folder, "main.tf")

            elapsed   = time.time() - start_time
            rate      = local_idx / elapsed if elapsed > 0 else 0.1
            remaining = len(pending) - local_idx
            eta_secs  = int(remaining / rate) if rate > 0 else 0
            eta_str   = f"{eta_secs//60}m{eta_secs%60:02d}s"

            print(f"\n{BOLD}[{global_idx}/{total}]{RESET}  {CYAN}{folder}{RESET}  "
                  f"{YELLOW}(ETA ~{eta_str}){RESET}")

            resource_prefix = folder.split("_")[0]
            outcome         = _run_no_witness_case(tf_file, folder)
            result          = outcome["result"]
            attempts        = outcome["attempts"]
            retry_hist      = outcome["retry_history"]
            final_verdict   = outcome["final_verdict"]
            z3_initial      = outcome["z3_initial"]
            hallucination   = result == "HALLUCINATION"
            retry_str       = " | ".join(retry_hist) if retry_hist else "N/A"

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

    avg           = (sum(all_attempts) / len(all_attempts)) if all_attempts else 0.0
    total_elapsed = int(time.time() - start_time)
    total_run     = len(pending)

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}ABLATION CONDITION B (NO-WITNESS) - SESSION COMPLETE{RESET}")
    print(f"{BOLD}Condition : No-Witness (k_max={K_MAX})  |  Provider: {condition_label}{RESET}")
    print(f"{'='*65}")
    print(f"Cases evaluated this session     : {total_run}")
    print(f"Total elapsed                    : {total_elapsed//60}m{total_elapsed%60:02d}s")
    print(f"{GREEN}Naturally Secure (PASS)          : {pass_count}{RESET}")
    print(f"{GREEN}Fixed (Z3 verified, no witness)  : {fixed_count}{RESET}")
    print(f"{RED}Persistent Hallucination         : {hallucination_count}{RESET}")
    print(f"{YELLOW}Avg LLM Attempts (fixed only)    : {avg:.2f}{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"\n{CYAN}Full dataset: {csv_file}{RESET}")
    print(f"{CYAN}Re-invoke to resume from checkpoint if interrupted.{RESET}\n")


if __name__ == "__main__":
    args = _parse_args()
    run_no_witness_ablation(provider=args.provider)
