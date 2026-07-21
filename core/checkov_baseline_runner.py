"""
checkov_baseline_runner.py — Sentinel-Mesh Static-Analysis Baseline Evaluator
===============================================================================
Module Purpose
--------------
Implements the "Checkov-Feedback" experimental condition for comparative
evaluation against the Sentinel-Mesh neuro-symbolic pipeline (CloudFix-Bench,
N=105). This module constitutes the ablation baseline in which the symbolic
oracle (Z3 SMT solver) is replaced by a static rule-based linter (Checkov),
isolating the contribution of formal verification to the overall remediation
rate.

Evaluation Protocol
-------------------
For each benchmark case:
  1. Invokes the Checkov CLI via subprocess against the target HCL artefact,
     requesting machine-readable JSON diagnostic output.
  2. Serializes the linter-derived diagnostic payload (failed check IDs and
     canonical check descriptions) into a structured context string.
  3. Constructs a single-pass remediation prompt embedding the broken HCL
     source and the Checkov static-analysis context. No SMT variables, CPM
     zone encodings, or Z3 counterexample witnesses are introduced.
  4. Invokes stochastic LLM inference under static context (k=1, no retry
     loop), constituting a strict one-shot evaluation condition.
  5. Submits the synthesized patch to the Z3-based global_verifier as an
     impartial, condition-blind judge. The verifier has no access to the
     Checkov diagnostic payload and operates exclusively on CPM invariants.
  6. Persists the per-case result tuple atomically to a provider-scoped CSV
     log after each case, ensuring recoverability under process interruption.

Isolation Guarantees
--------------------
- The LLM inference prompt contains zero Z3/SMT constructs.
- The verifier (judge) is condition-blind: it receives only the patched HCL.
- Provider lock and checkpoint-resume semantics are structurally identical to
  experiment_runner.py, ensuring experimental comparability.

Academic Context
----------------
This baseline operationalises "Reviewer 2" comparative requirement: measuring
whether linter-derived text diagnostics alone are sufficient to guide LLM
remediation to a formally verified secure state, without the precision of
symbolic counterexample witnesses.

References
----------
- Checkov: Infrastructure-as-Code static analysis framework (Bridgecrew, 2021)
- CloudFix-Bench: 105-case IaC security remediation benchmark (this work)
- Clarke et al., Model Checking, MIT Press, 2000 (Z3 judge basis)
"""

from __future__ import annotations

import sys
import os
import csv
import json
import time
import random
import argparse
import tempfile
import subprocess
from datetime import datetime

# ---------------------------------------------------------------------------
# Resolve project root so the module is importable from any working directory.
# ---------------------------------------------------------------------------
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier
from core.llm_agent import get_remediation_patch, inter_case_sleep, set_provider_lock

# ---------------------------------------------------------------------------
# ANSI terminal colour codes — sourced from orchestrator.py colour palette.
# All log output is structured using these codes for pipeline consistency.
# ---------------------------------------------------------------------------
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
BASE_DIR        = "benchmark/test_cases"
OUTPUT_CSV      = "logs/research_data_checkov_baseline.csv"
PATCHES_DIR     = "logs/patches"

# CSV schema — structurally aligned with experiment_runner.py for
# cross-condition comparative analysis without schema transformation.
FIELDNAMES = [
    "timestamp",
    "case_id",
    "resource",
    "checkov_checks_failed",
    "checkov_diagnostic",
    "checkov_status",
    "llm_patch_parsed",
    "z3_verdict",
    "result",
]


# ---------------------------------------------------------------------------
# Checkpoint Resume
# ---------------------------------------------------------------------------

def _load_completed_cases(csv_path: str) -> set:
    """
    Deserialises the set of case_id values already persisted to `csv_path`.

    Enables idempotent re-invocation: cases present in the log are excluded
    from the pending queue, preserving existing observations without
    duplication across interrupted sessions.
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


# ---------------------------------------------------------------------------
# Checkov Linter Interface
# ---------------------------------------------------------------------------

def _invoke_checkov(tf_file_path: str) -> dict | None:
    """
    Invokes the Checkov CLI against `tf_file_path` and deserialises the
    machine-readable JSON diagnostic payload.

    The subprocess is invoked with ``--compact`` and ``--quiet`` to suppress
    decorative terminal output that would contaminate the JSON stream.
    Checkov exit codes 0 (all-pass) and 1 (violations found) are both treated
    as valid terminations; exit code 2 indicates a hard parse error.

    Returns
    -------
    dict | None
        Deserialised Checkov JSON result on success; None on subprocess
        failure or JSON decode error.
    """
    try:
        proc = subprocess.run(
            ["checkov", "-f", tf_file_path, "-o", "json", "--compact", "--quiet"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        raw = proc.stdout.strip()
        if not raw:
            print(f"      {YELLOW}[CHECKOV] Empty stdout — exit code {proc.returncode}{RESET}")
            return None
        # Checkov may emit a list (multi-framework) or a dict (single framework).
        # Normalise to dict form.
        payload = json.loads(raw)
        if isinstance(payload, list):
            # Merge results from multiple framework runs into a single dict.
            merged: dict = {"results": {"failed_checks": [], "passed_checks": []}}
            for entry in payload:
                if isinstance(entry, dict) and "results" in entry:
                    merged["results"]["failed_checks"].extend(
                        entry["results"].get("failed_checks", [])
                    )
                    merged["results"]["passed_checks"].extend(
                        entry["results"].get("passed_checks", [])
                    )
            return merged
        return payload
    except subprocess.TimeoutExpired:
        print(f"      {RED}[CHECKOV] Subprocess timeout exceeded (60s).{RESET}")
        return None
    except json.JSONDecodeError as exc:
        print(f"      {RED}[CHECKOV] JSON deserialisation failure: {exc}{RESET}")
        return None
    except FileNotFoundError:
        print(f"      {RED}[CHECKOV] Binary not found on PATH. Verify checkov installation.{RESET}")
        return None
    except Exception as exc:
        print(f"      {RED}[CHECKOV] Subprocess exception: {exc}{RESET}")
        return None


def _extract_diagnostics(checkov_payload: dict) -> tuple[list[dict], str]:
    """
    Extracts failed-check records from the Checkov JSON result structure and
    serialises them into a human-readable diagnostic context string suitable
    for LLM prompt embedding.

    Returns
    -------
    (failed_checks, diagnostic_string)
        failed_checks      : list of raw failed-check dicts from the payload.
        diagnostic_string  : newline-delimited serialisation of check_id and
                             check_name pairs for prompt construction.
    """
    results = checkov_payload.get("results", {})
    failed  = results.get("failed_checks", [])

    if not failed:
        return [], "NO_VIOLATIONS_DETECTED"

    lines: list[str] = []
    for chk in failed:
        check_id   = chk.get("check_id",   "UNKNOWN_ID")
        check_name = chk.get("check_name", "UNKNOWN_CHECK")
        resource   = chk.get("resource",   "unknown_resource")
        lines.append(f"{check_id}: {check_name} [resource: {resource}]")

    return failed, "\n".join(lines)


# ---------------------------------------------------------------------------
# Prompt Construction
# ---------------------------------------------------------------------------

def _build_checkov_prompt(broken_hcl: str, diagnostic_str: str) -> str:
    """
    Constructs the one-shot remediation prompt embedding the broken HCL source
    and the Checkov static-analysis diagnostic payload.

    Architectural constraint: this prompt must contain zero Z3/SMT constructs,
    CPM zone encodings, or formal counterexample witnesses. It constitutes the
    "static-analysis baseline" condition in the experimental ablation.
    """
    return (
        "You are a Senior Cloud Security Engineer specializing in Terraform and AWS security.\n\n"
        "TASK: Rewrite the following Terraform configuration to remediate all security "
        "violations identified by the Checkov static-analysis linter.\n\n"
        "STRICT RULES:\n"
        "- Return ONLY valid Terraform HCL code.\n"
        "- Do NOT include any explanation, markdown formatting, or backtick fences.\n"
        "- Do NOT alter resource names or logical topology unnecessarily.\n"
        "- Each remediation must directly address the Checkov check listed below.\n"
        "- Every attribute added must constitute syntactically valid Terraform HCL.\n\n"
        f"BROKEN TERRAFORM CODE:\n{broken_hcl}\n\n"
        f"CHECKOV STATIC ANALYSIS VIOLATIONS:\n{diagnostic_str}\n\n"
        "CORRECTED TERRAFORM CODE:"
    )


# ---------------------------------------------------------------------------
# Patch Normalisation
# ---------------------------------------------------------------------------

def _normalise_patch(raw_patch: str) -> str:
    """
    Normalises syntactical anomalies in LLM-generated HCL output by stripping
    markdown code-fence delimiters and extraneous whitespace tokens that would
    cause HCL2 parse failures.
    """
    return (
        raw_patch
        .replace("```terraform", "")
        .replace("```hcl", "")
        .replace("```", "")
        .strip()
    )


# ---------------------------------------------------------------------------
# CLI Argument Parser
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """
    Defines the CLI surface for the Checkov baseline runner.

    --provider restricts all LLM synthesis calls to a single provider by
    engaging a singleton dispatch lock in llm_agent prior to benchmark loop
    execution, eliminating cross-provider confounding in logged results.
    """
    parser = argparse.ArgumentParser(
        prog="checkov_baseline_runner",
        description=(
            "Sentinel-Mesh Checkov-Feedback Baseline Evaluator. "
            "Executes the static-analysis linter → LLM one-shot remediation "
            "pipeline across all CloudFix-Bench cases (N=105) and persists "
            "results to logs/research_data_checkov_baseline.csv."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Provider to model mapping:\n"
            "  gemini    gemini-flash-latest\n"
            "  groq      llama-3.3-70b-versatile\n"
            "  cerebras  gpt-oss-120b\n\n"
            "Output: logs/research_data_checkov_baseline.csv\n"
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
            "Omit for default rotation (Cerebras → Gemini → Groq)."
        ),
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# Main Evaluation Loop
# ---------------------------------------------------------------------------

def run_checkov_baseline(provider: str | None = None) -> None:
    """
    Entry point for a single Checkov-Feedback baseline evaluation session.

    Execution Protocol (per case)
    ------------------------------
    1. Linter invocation  : Checkov CLI → JSON diagnostic payload.
    2. Diagnostic extraction : failed check IDs + canonical descriptions.
    3. Prompt construction : static-analysis context only (no SMT constructs).
    4. LLM inference (k=1) : single stochastic synthesis attempt.
    5. Patch verification  : global_verifier (Z3, condition-blind judge).
    6. Atomic persistence  : CSV row written and flushed after each case.

    Parameters
    ----------
    provider : str | None
        When non-None, engages set_provider_lock before the benchmark loop,
        routing all get_remediation_patch calls to the specified provider.
    """
    os.makedirs("logs",      exist_ok=True)
    os.makedirs(PATCHES_DIR, exist_ok=True)

    # --- Engage provider lock before first benchmark case
    if provider is not None:
        set_provider_lock(provider)

    condition_label = provider.upper() if provider else "ROTATION (Cerebras→Gemini→Groq)"

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}{CYAN}  CHECKOV-FEEDBACK BASELINE EVALUATOR — Sentinel-Mesh{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"{CYAN}[CONFIG] Experimental condition : CHECKOV-FEEDBACK (Static Linter){RESET}")
    print(f"{CYAN}[CONFIG] LLM provider           : {condition_label}{RESET}")
    print(f"{CYAN}[CONFIG] Inference attempts (k) : 1  [strict one-shot]{RESET}")
    print(f"{CYAN}[CONFIG] Judge                  : global_verifier (Z3, condition-blind){RESET}")
    print(f"{CYAN}[CONFIG] Output CSV             : {OUTPUT_CSV}{RESET}")
    print(f"{BOLD}{'='*65}{RESET}\n")

    # --- Enumerate benchmark cases
    all_folders = sorted([
        f for f in os.listdir(BASE_DIR)
        if os.path.isdir(os.path.join(BASE_DIR, f))
        and os.path.exists(os.path.join(BASE_DIR, f, "main.tf"))
    ])
    total = len(all_folders)
    print(f"{CYAN}[INGESTION] Discovered {total} benchmark cases in {BASE_DIR}/{RESET}")

    # --- Checkpoint resume
    completed = _load_completed_cases(OUTPUT_CSV)
    pending   = [f for f in all_folders if f not in completed]

    if completed:
        print(f"{YELLOW}[RESUME] {len(completed)} cases already persisted — "
              f"resuming from case {len(completed)+1}/{total}{RESET}")
    else:
        print(f"{BOLD}{CYAN}[START] Initiating evaluation over {total} cases{RESET}")

    if not pending:
        print(f"{GREEN}[DONE] All {total} cases already completed for this condition.{RESET}")
        return

    # --- Open CSV in append mode; emit header only on file creation
    file_exists = os.path.exists(OUTPUT_CSV) and os.path.getsize(OUTPUT_CSV) > 0
    csv_handle  = open(OUTPUT_CSV, mode="a", newline="", encoding="utf-8")
    writer      = csv.DictWriter(csv_handle, fieldnames=FIELDNAMES)
    if not file_exists:
        writer.writeheader()

    # --- Session counters
    pass_count          = 0
    fixed_count         = 0
    hallucination_count = 0
    anomaly_count       = 0
    checkov_error_count = 0
    start_time          = time.time()

    try:
        for local_idx, folder in enumerate(pending, 1):
            global_idx = len(completed) + local_idx
            tf_file    = os.path.join(BASE_DIR, folder, "main.tf")

            # Rolling ETA estimate
            elapsed   = time.time() - start_time
            rate      = local_idx / elapsed if elapsed > 0 else 0.1
            remaining = len(pending) - local_idx
            eta_secs  = int(remaining / rate) if rate > 0 else 0
            eta_str   = f"{eta_secs//60}m{eta_secs%60:02d}s"

            print(f"\n{BOLD}{'─'*65}{RESET}")
            print(f"{BOLD}[{global_idx}/{total}]{RESET}  {CYAN}{folder}{RESET}  "
                  f"{YELLOW}(ETA ~{eta_str}){RESET}")
            print(f"{CYAN}[TARGET]{RESET} {tf_file}")
            print(f"{CYAN}[TIMESTAMP]{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

            resource_prefix = folder.split("_")[0]

            # ------------------------------------------------------------------
            # PHASE 1: Linter Invocation
            # ------------------------------------------------------------------
            print(f"\n{BOLD}[PHASE 1] Checkov Static-Analysis Linter Invocation{RESET}")
            checkov_payload = _invoke_checkov(tf_file)

            if checkov_payload is None:
                # Subprocess or parse failure — log and skip per error-handling spec
                print(f"      {RED}[CHECKOV ERROR] Diagnostic payload unavailable — skipping case.{RESET}")
                checkov_error_count += 1
                writer.writerow({
                    "timestamp":          datetime.now().strftime("%H:%M:%S"),
                    "case_id":            folder,
                    "resource":           resource_prefix,
                    "checkov_checks_failed": 0,
                    "checkov_diagnostic": "CHECKOV_INVOCATION_ERROR",
                    "checkov_status":     "ERROR",
                    "llm_patch_parsed":   False,
                    "z3_verdict":         "N/A",
                    "result":             "CHECKOV_ERROR",
                })
                csv_handle.flush()
                inter_case_sleep(global_idx)
                continue

            failed_checks, diagnostic_str = _extract_diagnostics(checkov_payload)

            if diagnostic_str == "NO_VIOLATIONS_DETECTED":
                # Checkov returned all-pass — anomaly case per error-handling spec
                print(f"      {YELLOW}[ANOMALY] Checkov reports no violations on broken fixture "
                      f"— recording as anomaly.{RESET}")
                anomaly_count += 1
                writer.writerow({
                    "timestamp":          datetime.now().strftime("%H:%M:%S"),
                    "case_id":            folder,
                    "resource":           resource_prefix,
                    "checkov_checks_failed": 0,
                    "checkov_diagnostic": "NO_VIOLATIONS_DETECTED",
                    "checkov_status":     "ANOMALY",
                    "llm_patch_parsed":   False,
                    "z3_verdict":         "N/A",
                    "result":             "ANOMALY",
                })
                csv_handle.flush()
                inter_case_sleep(global_idx)
                continue

            n_failed = len(failed_checks)
            print(f"      {RED}[LINTER RESULT]{RESET} {n_failed} check(s) failed:")
            for line in diagnostic_str.splitlines():
                print(f"        {YELLOW}↳ {line}{RESET}")

            # ------------------------------------------------------------------
            # PHASE 2: One-Shot LLM Remediation under Static-Analysis Context
            # ------------------------------------------------------------------
            print(f"\n{BOLD}[PHASE 2] One-Shot LLM Synthesis (k=1, static context){RESET}")

            with open(tf_file, "r", encoding="utf-8") as fh:
                original_hcl = fh.read()

            # Construct Checkov-only prompt — zero SMT/Z3 constructs
            prompt = _build_checkov_prompt(original_hcl, diagnostic_str)

            # Invoke stochastic LLM inference under static context (attempt=1, no retry)
            print(f"      {MAGENTA}[LLM] Invoking single-pass synthesis — provider: {condition_label}{RESET}")
            raw_patch = get_remediation_patch(original_hcl, diagnostic_str, attempt=1)

            patch_parsed  = True
            clean_patch   = _normalise_patch(raw_patch)

            # Detect synthesis failure token
            if clean_patch.startswith("# ERROR:") or not clean_patch.strip():
                print(f"      {RED}[LLM ERROR] Synthesis failed — no valid patch generated.{RESET}")
                patch_parsed = False
                # Persist raw string to patches directory for forensic review
                forensic_path = os.path.join(
                    PATCHES_DIR,
                    f"checkov_baseline_{folder}_forensic.tf"
                )
                try:
                    with open(forensic_path, "w", encoding="utf-8") as fh:
                        fh.write(raw_patch)
                    print(f"      {YELLOW}[FORENSIC] Raw output written to: {forensic_path}{RESET}")
                except Exception as exc:
                    print(f"      {RED}[FORENSIC] Write failure: {exc}{RESET}")

                hallucination_count += 1
                writer.writerow({
                    "timestamp":          datetime.now().strftime("%H:%M:%S"),
                    "case_id":            folder,
                    "resource":           resource_prefix,
                    "checkov_checks_failed": n_failed,
                    "checkov_diagnostic": diagnostic_str[:500],
                    "checkov_status":     "FAILED",
                    "llm_patch_parsed":   False,
                    "z3_verdict":         "LLM_SYNTHESIS_FAILURE",
                    "result":             "HALLUCINATION",
                })
                csv_handle.flush()
                inter_case_sleep(global_idx)
                continue

            # ------------------------------------------------------------------
            # PHASE 3: Impartial Z3 Verification (Condition-Blind Judge)
            # ------------------------------------------------------------------
            print(f"\n{BOLD}[PHASE 3] Z3 Formal Verification — Impartial Judge{RESET}")
            print(f"      {CYAN}↳ Submitting synthesised patch to global_verifier (no Checkov context){RESET}")

            temp_path: str | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    suffix=".tf", mode="w", delete=False, encoding="utf-8"
                ) as tmp:
                    tmp.write(clean_patch)
                    temp_path = tmp.name

                patch_data = parse_hcl(temp_path)

                if "error" in patch_data:
                    # HCL2 parse failure — treat as hallucination; persist for forensic review
                    print(f"      {RED}[PARSE ERROR] HCL2 parse failure on synthesised patch: "
                          f"{patch_data['error']}{RESET}")
                    patch_parsed = False
                    forensic_path = os.path.join(
                        PATCHES_DIR,
                        f"checkov_baseline_{folder}_parse_error.tf"
                    )
                    try:
                        with open(forensic_path, "w", encoding="utf-8") as fh:
                            fh.write(clean_patch)
                        print(f"      {YELLOW}[FORENSIC] Unparseable patch written to: {forensic_path}{RESET}")
                    except Exception as exc:
                        print(f"      {RED}[FORENSIC] Write failure: {exc}{RESET}")

                    z3_verdict = f"HCL_PARSE_ERROR: {patch_data['error'][:200]}"
                    result_str = "HALLUCINATION"
                    hallucination_count += 1
                else:
                    z3_verdict = global_verifier(patch_data)
                    if "PASS" in z3_verdict:
                        result_str = "FIXED"
                        fixed_count += 1
                        print(f"      {GREEN}[Z3 PASS] Patch satisfies all Cloud Perimeter invariants.{RESET}")
                    else:
                        result_str = "HALLUCINATION"
                        hallucination_count += 1
                        print(f"      {RED}[Z3 FAIL] Patch rejected: {z3_verdict[:120]}{RESET}")

            finally:
                if temp_path and os.path.exists(temp_path):
                    os.remove(temp_path)

            # ------------------------------------------------------------------
            # PHASE 4: Atomic CSV Persistence
            # ------------------------------------------------------------------
            writer.writerow({
                "timestamp":             datetime.now().strftime("%H:%M:%S"),
                "case_id":               folder,
                "resource":              resource_prefix,
                "checkov_checks_failed": n_failed,
                "checkov_diagnostic":    diagnostic_str[:500],
                "checkov_status":        "FAILED",
                "llm_patch_parsed":      patch_parsed,
                "z3_verdict":            z3_verdict,
                "result":                result_str,
            })
            csv_handle.flush()

            # Console per-case summary
            colour = GREEN if result_str == "FIXED" else RED
            print(f"\n      {colour}[RESULT] {result_str}{RESET}  "
                  f"— checks_failed={n_failed}  "
                  f"patch_parsed={patch_parsed}")

            # Adaptive inter-case delay with uniform random jitter
            inter_case_sleep(global_idx)

    finally:
        csv_handle.close()

    # --------------------------------------------------------------------------
    # Session Summary
    # --------------------------------------------------------------------------
    total_elapsed = int(time.time() - start_time)
    total_run     = len(pending)
    remediation_rate = (fixed_count / total_run * 100) if total_run > 0 else 0.0

    print(f"\n{BOLD}{'='*65}{RESET}")
    print(f"{BOLD}CHECKOV-FEEDBACK BASELINE — SESSION COMPLETE{RESET}")
    print(f"{BOLD}Condition : CHECKOV (Static Linter, k=1)  |  Provider: {condition_label}{RESET}")
    print(f"{'='*65}")
    print(f"Cases evaluated this session : {total_run}")
    print(f"Total elapsed                : {total_elapsed//60}m{total_elapsed%60:02d}s")
    print(f"{GREEN}One-shot FIXED (Z3 verified)  : {fixed_count}{RESET}")
    print(f"{RED}HALLUCINATION (Z3 rejected)   : {hallucination_count}{RESET}")
    print(f"{YELLOW}ANOMALY (Checkov all-pass)    : {anomaly_count}{RESET}")
    print(f"{RED}CHECKOV ERROR (skipped)       : {checkov_error_count}{RESET}")
    print(f"{CYAN}One-shot remediation rate     : {remediation_rate:.1f}%{RESET}")
    print(f"{BOLD}{'='*65}{RESET}")
    print(f"\n{CYAN}Full dataset: {OUTPUT_CSV}{RESET}")
    print(f"{CYAN}Re-invoke to resume from checkpoint if interrupted.{RESET}\n")


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    args = _parse_args()
    run_checkov_baseline(provider=args.provider)
