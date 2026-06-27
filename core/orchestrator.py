import sys
import os
import time
import tempfile
from datetime import datetime

# ANSI terminal colour codes for structured audit log output.
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers.hcl_to_json import parse_hcl
from core.verifier import global_verifier, global_verifier_with_patch_proof
from core.llm_agent import get_remediation_patch

MAX_RETRIES = 5  # Maximum LLM synthesis attempts before the case is classified as a persistent repair failure.

def run_sentinel_mesh(tf_file_path):
    """
    The Formal Verification & Neuro-Remediation Closed-Loop.

    Returns a dict with:
      - result:         "PASS" | "FIXED" | "HALLUCINATION"
      - attempts:       number of LLM calls made (0 if initially PASS)
      - retry_history:  list of Z3 verdicts per attempt
      - final_verdict:  final Z3 output string
    """
    case_name = os.path.basename(os.path.dirname(tf_file_path))

    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}[AUDIT LOG]{RESET} Sentinel-Mesh Scanning: {BOLD}{case_name}{RESET}")
    print(f"{CYAN}[TARGET]{RESET}    {tf_file_path}")
    print(f"{CYAN}[TIMESTAMP]{RESET} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{BOLD}{'='*60}{RESET}")

    # ---
    print(f"\n{BOLD}[*] PHASE 1: Symbolic Boundary Verification (Z3-SMT){RESET}")
    data = parse_hcl(tf_file_path)
    initial_result = global_verifier(data)

    # Substring match is intentional: the verifier prefixes all passing verdicts with "PASS".
    if "PASS" in initial_result:
        print(f"{GREEN}[SUCCESS] Formal Proof: Configuration satisfies all security invariants.{RESET}")
        return {
            "result": "PASS",
            "attempts": 0,
            "retry_history": [],
            "final_verdict": initial_result
        }

    print(f"{RED}[VIOLATION] {initial_result}{RESET}")

    # ---
    print(f"\n{BOLD}[*] PHASE 2: Closed-Loop Neuro-Remediation (LLM + Z3 Retry){RESET}")

    with open(tf_file_path, "r") as f:
        original_code = f.read()

    # The current violation message provided to the LLM at each iteration.
    current_violation = initial_result
    retry_history = []   # Stores Z3 verdict string for each attempt
    attempt = 0

    while attempt < MAX_RETRIES:
        attempt += 1
        print(f"\n{MAGENTA}[ATTEMPT {attempt}/{MAX_RETRIES}]{RESET} Requesting patch from LLM...")
        print(f"      {YELLOW}↳ Feeding Z3 rejection back to LLM: {current_violation[:80]}...{RESET}")

        # LLM generates a patch informed by the Z3 rejection reason
        raw_patch = get_remediation_patch(original_code, current_violation, attempt)
        clean_patch = (
            raw_patch
            .replace("```terraform", "")
            .replace("```hcl", "")
            .replace("```", "")
            .strip()
        )

        # ---
        print(f"      {CYAN}↳ Running Z3 Formal Verification on generated patch...{RESET}")

        with tempfile.NamedTemporaryFile(suffix=".tf", mode='w', delete=False) as tmp:
            tmp.write(clean_patch)
            temp_path = tmp.name

        try:
            patch_data = parse_hcl(temp_path)
            # Pattern 3: invoke the SMT-based dual-solver patch safety proof (refinement check).
            z3_result = global_verifier_with_patch_proof(
                broken_data=parse_hcl(tf_file_path),
                patch_data=patch_data,
                violation_msg=current_violation,
                resource_name=case_name
            )
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)

        retry_history.append(z3_result)

        if "PASS" in z3_result:
            print(f"{GREEN}[PASS] Attempt {attempt}: Z3 Formally Verified - Patch is SECURE!{RESET}")
            print(f"{GREEN}[PROVEN] Patch accepted after {attempt} attempt(s).{RESET}")
            return {
                "result": "FIXED",
                "attempts": attempt,
                "retry_history": retry_history,
                "final_verdict": z3_result
            }
        else:
            print(f"{RED}[FAIL] Attempt {attempt}: Z3 Rejected - {z3_result}{RESET}")
            print(f"      {YELLOW}↳ Patch rejected. Feeding updated violation context to LLM for retry...{RESET}")
            # Update context so LLM sees the newest rejection on the next loop
            current_violation = z3_result

    # ---
    print(f"\n{RED}[CRITICAL] LLM failed to produce a valid patch after {MAX_RETRIES} attempts.{RESET}")
    print(f"{RED}[CONCLUSION] Persistent hallucination on: {case_name}{RESET}")
    return {
        "result": "HALLUCINATION",
        "attempts": attempt,
        "retry_history": retry_history,
        "final_verdict": retry_history[-1] if retry_history else "No patch generated"
    }


if __name__ == "__main__":
    base_dir = "benchmark/test_cases"

    if len(sys.argv) > 1:
        outcome = run_sentinel_mesh(sys.argv[1])
        print(f"\n{BOLD}Result:{RESET}   {outcome['result']}")
        print(f"{BOLD}Attempts:{RESET} {outcome['attempts']}")
        print(f"{BOLD}Retry History:{RESET}")
        for i, verdict in enumerate(outcome['retry_history'], 1):
            print(f"  Attempt {i}: {verdict}")
    else:
        print(f"{CYAN}[SYSTEM] No target specified. Starting Dynamic Discovery...{RESET}")
        folders = sorted([
            f for f in os.listdir(base_dir)
            if os.path.isdir(os.path.join(base_dir, f))
        ])

        stats = {"PASS": 0, "FIXED": 0, "HALLUCINATION": 0}
        total_attempts = []

        for folder in folders:
            tf_file = os.path.join(base_dir, folder, "main.tf")
            if os.path.exists(tf_file):
                outcome = run_sentinel_mesh(tf_file)
                stats[outcome["result"]] += 1
                if outcome["attempts"] > 0:
                    total_attempts.append(outcome["attempts"])
                time.sleep(1)

        avg_attempts = (sum(total_attempts) / len(total_attempts)) if total_attempts else 0

        print(f"\n{BOLD}{'='*60}{RESET}")
        print(f"{BOLD}FINAL BENCHMARK SUMMARY{RESET}")
        print(f"{'='*60}")
        print(f"{GREEN}Naturally Secure:         {stats['PASS']}{RESET}")
        print(f"{CYAN}Successfully Fixed:        {stats['FIXED']}{RESET}")
        print(f"{RED}Persistent Hallucination:  {stats['HALLUCINATION']}{RESET}")
        print(f"{YELLOW}Avg Attempts to Fix:       {avg_attempts:.2f}{RESET}")
        print(f"{BOLD}{'='*60}{RESET}")