"""
llm_agent.py: Sentinel-Mesh LLM Remediation Agent
====================================================
Providers (in priority order):
  1. Cerebras: provides low-latency inference with a permissive free-tier quota
  2. Gemini: gemini-2.0-flash → gemini-1.5-flash (free tier, quota per minute)
  3. Groq: llama-3.3-70b-versatile (free tier, daily token limit)

Rate Limit Strategy:
  - Per-provider cooldown tracker: if a provider hits 429, the provider is excluded
    from the current attempt for COOLDOWN_SECONDS before being tried again,
    avoiding unnecessary blocking delays.
  - Provider order rotates per attempt to spread load:
      Attempt 1 → Cerebras → Gemini → Groq
      Attempt 2 → Groq     → Cerebras → Gemini
      Attempt 3 → Gemini   → Groq     → Cerebras
  - Between cases: adaptive inter-case delay with uniform random jitter + checkpoint pauses every 10 cases.
"""

from __future__ import annotations  # defer annotation eval: supports str | None on Python < 3.10
import os
import time
import random
from dotenv import load_dotenv

load_dotenv()

GENAI_API_KEY    = os.getenv("GENAI_API_KEY")
GROQ_API_KEY     = os.getenv("GROQ_API_KEY")
CEREBRAS_API_KEY = os.getenv("CEREBRAS_API_KEY")

# How long to skip a provider after it returns 429
COOLDOWN_SECONDS = 60

# Per-provider cooldown timestamps (module-level - persists across all cases in one run)
_cooldown_until = {"gemini": 0.0, "groq": 0.0, "cerebras": 0.0}

# --- Initialize clients
gemini_client   = None
groq_client     = None
cerebras_client = None

if GENAI_API_KEY:
    try:
        from google import genai
        gemini_client = genai.Client(api_key=GENAI_API_KEY)
        print("[llm_agent] Gemini client initialized.")
    except Exception as e:
        print(f"[llm_agent] Gemini init failed: {e}")

if GROQ_API_KEY:
    try:
        from groq import Groq
        groq_client = Groq(api_key=GROQ_API_KEY)
        print("[llm_agent] Groq client initialized.")
    except Exception as e:
        print(f"[llm_agent] Groq init failed: {e}")

if CEREBRAS_API_KEY:
    try:
        from cerebras.cloud.sdk import Cerebras
        cerebras_client = Cerebras(api_key=CEREBRAS_API_KEY)
        print("[llm_agent] Cerebras client initialized.")
    except Exception as e:
        print(f"[llm_agent] Cerebras init failed: {e}")

# Model identifiers: Cerebras and Groq identifiers are pinned versioned strings.
# The Gemini entry uses the floating alias gemini-flash-latest, which resolved
# to gemini-1.5-flash-002 at the time of evaluation (see paper Section V).
GEMINI_MODELS  = ["gemini-flash-latest", "gemini-robotics-er-1.5-preview"]
GROQ_MODEL     = "llama-3.3-70b-versatile"
CEREBRAS_MODEL = "gpt-oss-120b"

# --- Provider rotation schedule (maps attempt index → ordered fallback list)
# Rotation distributes quota pressure across providers; index wraps via .get().
_PROVIDER_ROTATION = {
    1: ["cerebras", "gemini", "groq"],
    2: ["groq",     "cerebras", "gemini"],
    3: ["gemini",   "groq",     "cerebras"],
}

# --- Provider lock: isolates a single provider for controlled benchmark runs
# None  → standard rotation (multi-provider, exploratory mode).
# str   → singleton dispatch - all synthesis calls routed exclusively to this
#         provider, eliminating cross-provider confounding in logged results.
_LOCKED_PROVIDER: str | None = None


def set_provider_lock(provider: str | None) -> None:
    """
    Pins all subsequent `get_remediation_patch` calls to `provider`.

    Asserts that the supplied identifier resolves to an initialized client;
    raises ValueError on unrecognized or unconfigured providers so the runner
    raises ValueError prior to benchmark loop execution rather than silently degrading.

    Parameters
    ----------
    provider : str | None
        One of {'gemini', 'groq', 'cerebras'}, or None to restore rotation.
    """
    global _LOCKED_PROVIDER
    valid = {"gemini", "groq", "cerebras"}
    if provider is not None:
        if provider not in valid:
            raise ValueError(f"[llm_agent] Unknown provider '{provider}'. Valid: {valid}")
        client_map = {
            "gemini":   gemini_client,
            "groq":     groq_client,
            "cerebras": cerebras_client,
        }
        if client_map[provider] is None:
            raise ValueError(
                f"[llm_agent] Provider '{provider}' requested but client failed to initialize. "
                "Verify the corresponding API key in .env."
            )
    _LOCKED_PROVIDER = provider
    if provider:
        print(f"[llm_agent] Provider lock engaged: all synthesis calls → {provider.upper()}")


def _is_cooling(provider):
    return time.time() < _cooldown_until[provider]


def _set_cooldown(provider):
    _cooldown_until[provider] = time.time() + COOLDOWN_SECONDS
    print(f"      [llm] {provider.upper()} rate-limited - skipping for {COOLDOWN_SECONDS}s")


def _build_prompt(broken_code, z3_error):
    return (
        "You are a Senior Cloud Security Engineer specializing in Terraform and AWS security.\n\n"
        "TASK: Rewrite the following Terraform configuration to fix the security violation described below.\n\n"
        "STRICT RULES:\n"
        "- Return ONLY valid Terraform HCL code.\n"
        "- Do NOT include any explanation, markdown, or backticks.\n"
        "- Do NOT change resource names or logical structure unnecessarily.\n"
        "- The fix must directly address the VERIFICATION ERROR below.\n"
        "- Every attribute you add must be syntactically valid Terraform HCL.\n\n"
        f"BROKEN TERRAFORM CODE:\n{broken_code}\n\n"
        f"FORMAL VERIFICATION ERROR (from Z3 SMT solver):\n{z3_error}\n\n"
        "CORRECTED TERRAFORM CODE:"
    )


def _try_cerebras(prompt):
    if not cerebras_client:
        return None
    if _is_cooling("cerebras"):
        print("      [llm] Cerebras cooling down - skip")
        return None
    print(f"      [llm] Trying Cerebras ({CEREBRAS_MODEL})...")
    try:
        resp = cerebras_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=CEREBRAS_MODEL,
            temperature=0.1,
            max_tokens=2048,
        )
        text = resp.choices[0].message.content.strip()
        if text:
            print("      [llm] Cerebras responded.")
            return text
    except Exception as e:
        err = str(e)
        if "429" in err or "rate" in err.lower() or "limit" in err.lower():
            _set_cooldown("cerebras")
        else:
            print(f"      [llm] Cerebras error: {err[:100]}")
    return None


def _try_gemini(prompt):
    if not gemini_client:
        return None
    if _is_cooling("gemini"):
        print("      [llm] Gemini cooling down - skip")
        return None
    for model_id in GEMINI_MODELS:
        print(f"      [llm] Trying Gemini ({model_id})...")
        try:
            resp = gemini_client.models.generate_content(model=model_id, contents=prompt)
            if resp and resp.text and resp.text.strip():
                print(f"      [llm] Gemini {model_id} responded.")
                return resp.text.strip()
        except Exception as e:
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err or "quota" in err.lower():
                _set_cooldown("gemini")
                return None   # all Gemini models share quota - stop trying
            print(f"      [llm] Gemini {model_id} error: {err[:100]}")
    return None


def _try_groq(prompt):
    if not groq_client:
        return None
    if _is_cooling("groq"):
        print("      [llm] Groq cooling down - skip")
        return None
    print(f"      [llm] Trying Groq ({GROQ_MODEL})...")
    try:
        resp = groq_client.chat.completions.create(
            messages=[{"role": "user", "content": prompt}],
            model=GROQ_MODEL,
            temperature=0.1,
            max_tokens=2048,
        )
        text = resp.choices[0].message.content.strip()
        if text:
            print("      [llm] Groq responded.")
            return text
    except Exception as e:
        err = str(e)
        if "429" in err or "rate" in err.lower():
            _set_cooldown("groq")
        else:
            print(f"      [llm] Groq error: {err[:100]}")
    return None


def get_remediation_patch(broken_code: str, z3_error: str, attempt: int = 1) -> str:
    """
    Synthesizes a security-compliant Terraform patch via the active LLM backend.

    Dispatch mode is governed by `_LOCKED_PROVIDER`:
      - None  → rotation per `_PROVIDER_ROTATION[attempt]`; distributes quota load.
      - str   → singleton dispatch to the locked provider only; no fallback to
                other providers, ensuring provider identity is a controlled
                independent variable across benchmark conditions.

    Cooldown semantics apply in both modes: a 429 on the locked provider
    triggers a bounded wait-and-retry rather than silent fallback.
    """
    prompt  = _build_prompt(broken_code, z3_error)
    callers = {
        "cerebras": lambda: _try_cerebras(prompt),
        "gemini":   lambda: _try_gemini(prompt),
        "groq":     lambda: _try_groq(prompt),
    }

    # --- Locked-provider mode: singleton dispatch, no cross-provider fallback
    if _LOCKED_PROVIDER is not None:
        print(f"      [llm] Attempt {attempt} - locked provider: {_LOCKED_PROVIDER.upper()}")
        result = callers[_LOCKED_PROVIDER]()
        if result:
            return result
        # Locked provider is cooling; bounded wait, then one retry.
        wait = 20 + random.randint(0, 10)
        print(f"      [llm] {_LOCKED_PROVIDER.upper()} cooling - waiting {wait}s, then retrying...")
        time.sleep(wait)
        result = callers[_LOCKED_PROVIDER]()
        if result:
            return result
        print(f"      [llm] {_LOCKED_PROVIDER.upper()} failed on retry.")
        return f"# ERROR: Locked provider '{_LOCKED_PROVIDER}' failed or rate-limited."

    # --- Rotation mode: distribute load across provider priority list
    rotation = _PROVIDER_ROTATION.get(attempt, _PROVIDER_ROTATION[1])
    print(f"      [llm] Attempt {attempt} - rotation: {' -> '.join(p.upper() for p in rotation)}")

    for provider in rotation:
        result = callers[provider]()
        if result:
            return result

    # All providers failed/cooling - bounded wait, then reverse-order retry.
    wait = 20 + random.randint(0, 10)
    print(f"      [llm] All providers busy - waiting {wait}s then retrying...")
    time.sleep(wait)

    for provider in reversed(rotation):
        result = callers[provider]()
        if result:
            return result

    print("      [llm] All providers failed.")
    return "# ERROR: All LLM providers failed or rate-limited."


def inter_case_sleep(case_idx: int):
    """
    Adaptive inter-case delay:
    - Base delay of 3 seconds per case, calibrated to the most restrictive provider rate limit observed during evaluation.
    - Additional 15-second delay checkpoint every 10 cases.
    - Random jitter of +/- 2 seconds to desynchronize requests.
    """
    base   = 3
    bonus  = 15 if (case_idx % 10 == 0) else 0
    jitter = random.uniform(-2, 2)
    total  = max(1.0, base + bonus + jitter)
    if bonus:
        print(f"      [sleep] Checkpoint at case {case_idx} - sleeping {total:.1f}s")
    time.sleep(total)


if __name__ == "__main__":
    test_code = 'resource "aws_db_instance" "main" {\n  storage_encrypted = false\n}'
    test_err  = "FAIL: Cloud Perimeter Model - INV-2: sensitive data is unencrypted."
    print("=== Smoke Test ===")
    result = get_remediation_patch(test_code, test_err, attempt=1)
    print(f"Response: {result[:200]}")