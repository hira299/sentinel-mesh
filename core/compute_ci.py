"""
compute_ci.py: Confidence Interval Utility for Sentinel-Mesh Evaluation Metrics
=================================================================================
Reads benchmark CSV log files at runtime and computes 95% Wilson score confidence
intervals for all primary binomial proportions reported in:

  "Sentinel-Mesh: A Neuro-Symbolic Framework for Formally Verified
  Remediation of Cloud Misconfigurations,"

All rate values, case counts, and denominators are derived exclusively from
the raw CSV records at runtime via pandas. No benchmark statistics are
embedded in source code.

Wilson Score Interval
---------------------
Given k successes in n trials, the two-sided 95% Wilson score interval is:

    centre = (k + z^2/2) / (n + z^2)
    half   = z * sqrt(n*p*(1-p) + z^2/4) / (n + z^2)
    CI     = [centre - half, centre + half]

where z = 1.95996... (the 97.5th percentile of the standard normal, i.e.,
scipy.stats.norm.ppf(0.975)).  The Wilson interval is preferred over the
naive Wald interval for proportions close to 0 or 1 and small-to-moderate
sample sizes.

Usage
-----
    python -m core.compute_ci
    python -m core.compute_ci --csv-dir logs/

Compliance
----------
    Zero hardcoding: all metrics computed dynamically via pandas and scipy.
    ASCII-only comments: strict ASCII character set enforcement.
    Publication-grade output: LaTeX-formatted confidence interval strings.
"""

from __future__ import annotations

import argparse
import os
import sys

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Wilson Score Interval Implementation
# ---------------------------------------------------------------------------

def _wilson_ci(
    k: int,
    n: int,
    z: float = 1.9599639845400536,
) -> tuple[float, float]:
    """
    Compute the two-sided Wilson score confidence interval for a proportion.

    Parameters
    ----------
    k : int
        Number of successes (non-negative integer, 0 <= k <= n).
    n : int
        Total number of trials (positive integer).
    z : float
        Critical value from the standard normal distribution.
        Default is 1.9599..., the 97.5th percentile for a 95% two-sided CI.

    Returns
    -------
    (lo, hi) : tuple[float, float]
        Lower and upper bounds of the 95% Wilson score interval as
        proportions in [0, 1].  Returns (0.0, 0.0) when n == 0.
    """
    if n == 0:
        return (0.0, 0.0)

    # Attempt scipy import for numerically precise ppf; fall back to the
    # hard-coded asymptotic value that is accurate to 10 decimal places.
    try:
        from scipy.stats import norm  # type: ignore
        z = float(norm.ppf(0.975))
    except ImportError:
        pass  # retain the default z argument value

    p_hat = k / n
    z2 = z * z
    denominator = 1.0 + z2 / n
    centre = (p_hat + z2 / (2.0 * n)) / denominator
    half = (z / denominator) * np.sqrt(
        p_hat * (1.0 - p_hat) / n + z2 / (4.0 * n * n)
    )
    lo = float(np.clip(centre - half, 0.0, 1.0))
    hi = float(np.clip(centre + half, 0.0, 1.0))
    return (lo, hi)


# ---------------------------------------------------------------------------
# LaTeX Formatting Helper
# ---------------------------------------------------------------------------

def _latex_ci(label: str, k: int, n: int) -> str:
    """
    Format a Wilson score interval as a LaTeX math string.

    Produces output in the form:
        \\hat{p}_{label} = XX.X\\% \\; [YY.Y\\%, ZZ.Z\\%]

    Parameters
    ----------
    label : str
        Short LaTeX-safe descriptor for the proportion (e.g., 'RR').
    k : int
        Number of successes.
    n : int
        Total number of trials.

    Returns
    -------
    str
        A formatted LaTeX string suitable for direct inclusion in a
        tabular or equation environment.
    """
    if n == 0:
        return f"\\hat{{p}}_{{{label}}} = \\text{{N/A (n=0)}}"
    p = k / n
    lo, hi = _wilson_ci(k, n)
    return (
        f"\\hat{{p}}_{{{label}}} = {p * 100:.2f}\\% "
        f"\\; [{lo * 100:.2f}\\%, \\; {hi * 100:.2f}\\%]"
    )


# ---------------------------------------------------------------------------
# Per-Rate Computation Functions
# ---------------------------------------------------------------------------

def _compute_full_sentinel_mesh_rate(
    v100_path: str,
) -> tuple[int, int]:
    """
    Compute the Full Sentinel-Mesh remediation success count and total from
    logs/research_data_v100.csv.

    A case is counted as successfully remediated when hallucination == False
    (the case reached a valid Z3-verified patch within the k=5 retry budget).
    The v100 dataset uses a boolean 'hallucination' column; no 'result' column
    is present.

    Parameters
    ----------
    v100_path : str
        Filesystem path to research_data_v100.csv.

    Returns
    -------
    (k, n) : tuple[int, int]
        k = count of non-hallucination rows (remediated cases).
        n = total deduplicated row count.
    """
    df = pd.read_csv(v100_path)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()
    hall_mask = df['hallucination'].astype(str).str.lower().isin(['true', '1', 'yes'])
    k = int((~hall_mask).sum())
    n = len(df)
    return k, n


def _compute_one_shot_rate(
    v100_path: str,
) -> tuple[int, int]:
    """
    Compute the One-Shot (k=1, non-hallucination) success count and total
    from logs/research_data_v100.csv.

    A case is classified as one-shot when llm_attempts == 1 and the
    case was not a hallucination (result is valid).  The denominator is
    the total number of deduplicated rows (all benchmark cases), matching
    the definition in Table 3 of the paper.

    Parameters
    ----------
    v100_path : str
        Filesystem path to research_data_v100.csv.

    Returns
    -------
    (k, n) : tuple[int, int]
        k = count of cases resolved at attempt k=1 without hallucination.
        n = total deduplicated row count.
    """
    df = pd.read_csv(v100_path)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()
    df['llm_attempts'] = pd.to_numeric(df['llm_attempts'], errors='coerce').fillna(0)
    hall_mask = df['hallucination'].astype(str).str.lower().isin(['true', '1', 'yes'])
    one_shot_mask = (df['llm_attempts'] == 1) & (~hall_mask)
    k = int(one_shot_mask.sum())
    n = len(df)
    return k, n


def _compute_checkov_rate(
    checkov_path: str,
) -> tuple[int, int]:
    """
    Compute the Checkov static analysis baseline remediation count and total
    from logs/research_data_checkov_baseline.csv.

    A case is classified as remediated when result == 'FIXED'.  Cases with
    result in {'HALLUCINATION', 'ANOMALY', 'CHECKOV_ERROR'} are failures.

    Parameters
    ----------
    checkov_path : str
        Filesystem path to research_data_checkov_baseline.csv.

    Returns
    -------
    (k, n) : tuple[int, int]
        k = count of rows where result == 'FIXED'.
        n = total deduplicated row count.
    """
    df = pd.read_csv(checkov_path)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()
    k = int((df['result'] == 'FIXED').sum())
    n = len(df)
    return k, n


def _compute_no_witness_rate(
    no_witness_path: str,
) -> tuple[int, int]:
    """
    Compute the No-Witness ablation condition remediation count and total
    from logs/research_data_no_witness_groq.csv.

    This dataset uses the boolean 'hallucination' column (no 'result'
    column).  A case is remediated when hallucination == False.

    Parameters
    ----------
    no_witness_path : str
        Filesystem path to research_data_no_witness_groq.csv.

    Returns
    -------
    (k, n) : tuple[int, int]
        k = count of non-hallucination rows.
        n = total deduplicated row count.
    """
    df = pd.read_csv(no_witness_path)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()
    hall_mask = df['hallucination'].astype(str).str.lower().isin(['true', '1', 'yes'])
    k = int((~hall_mask).sum())
    n = len(df)
    return k, n


def _compute_wild_case_rate(
    wild_path: str,
) -> tuple[int, int]:
    """
    Compute the external wild-case generalisation remediation count and total
    from logs/research_data_wild_cases_groq.csv.

    A case is classified as remediated when result == 'FIXED'.

    Parameters
    ----------
    wild_path : str
        Filesystem path to research_data_wild_cases_groq.csv.

    Returns
    -------
    (k, n) : tuple[int, int]
        k = count of rows where result == 'FIXED'.
        n = total deduplicated row count.
    """
    df = pd.read_csv(wild_path)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()
    k = int((df['result'] == 'FIXED').sum())
    n = len(df)
    return k, n


# ---------------------------------------------------------------------------
# Main Reporting Function
# ---------------------------------------------------------------------------

def compute_and_print_all(csv_dir: str = 'logs') -> None:
    """
    Load all relevant benchmark CSV files from csv_dir, compute 95% Wilson
    score confidence intervals for all five primary proportions, and print
    both a plain-text summary and formatted LaTeX strings.

    Reported proportions
    --------------------
    1. Full Sentinel-Mesh Remediation Rate (RR)   -- research_data_v100.csv
    2. One-Shot Success Rate (OSR, k=1)            -- research_data_v100.csv
    3. Checkov Static Baseline Rate               -- research_data_checkov_baseline.csv
    4. No-Witness Ablation Rate                   -- research_data_no_witness_groq.csv
    5. Wild-Case Generalisation Rate              -- research_data_wild_cases_groq.csv

    Parameters
    ----------
    csv_dir : str
        Directory containing the benchmark CSV log files.
        Defaults to 'logs'.
    """
    v100_path       = os.path.join(csv_dir, 'research_data_v100.csv')
    checkov_path    = os.path.join(csv_dir, 'research_data_checkov_baseline.csv')
    no_witness_path = os.path.join(csv_dir, 'research_data_no_witness_groq.csv')
    wild_path       = os.path.join(csv_dir, 'research_data_wild_cases_groq.csv')

    for p in [v100_path, checkov_path, no_witness_path, wild_path]:
        if not (os.path.exists(p) and os.path.getsize(p) > 0):
            print(f'[compute_ci] ERROR: required CSV not found or empty: {p}')
            sys.exit(1)

    rr_k,  rr_n  = _compute_full_sentinel_mesh_rate(v100_path)
    osr_k, osr_n = _compute_one_shot_rate(v100_path)
    ck_k,  ck_n  = _compute_checkov_rate(checkov_path)
    nw_k,  nw_n  = _compute_no_witness_rate(no_witness_path)
    wi_k,  wi_n  = _compute_wild_case_rate(wild_path)

    metrics = [
        ('Full Sentinel-Mesh RR',       'RR',      rr_k,  rr_n),
        ('One-Shot Rate (k=1)',          'OSR',     osr_k, osr_n),
        ('Checkov Baseline Rate',        'CK',      ck_k,  ck_n),
        ('No-Witness Ablation Rate',     'NW',      nw_k,  nw_n),
        ('Wild-Case Generalisation Rate','WC',      wi_k,  wi_n),
    ]

    separator = '-' * 72

    print(separator)
    print('  Sentinel-Mesh -- 95% Wilson Score Confidence Intervals')
    print(separator)
    print(f'  {"Metric":<35} {"k":>5}  {"n":>5}   {"p":>7}   {"95% CI [lo, hi]"}')
    print(separator)

    latex_lines: list[str] = []

    for name, lbl, k, n in metrics:
        p    = k / n if n > 0 else 0.0
        lo, hi = _wilson_ci(k, n)
        print(
            f'  {name:<35} {k:>5}  {n:>5}   '
            f'{p * 100:>6.2f}%   '
            f'[{lo * 100:.2f}%, {hi * 100:.2f}%]'
        )
        latex_lines.append(_latex_ci(lbl, k, n))

    print(separator)
    print()
    print('  LaTeX-formatted strings for direct inclusion in manuscript:')
    print()
    for ln in latex_lines:
        print(f'  ${ln}$')
    print()
    print('  Note: Intervals computed via the Wilson score method.')
    print('  z = scipy.stats.norm.ppf(0.975) if scipy is available;')
    print('  otherwise z = 1.9599639845400536 (asymptotic value, 10 d.p.).')
    print(separator)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the confidence interval utility.
    """
    parser = argparse.ArgumentParser(
        prog='compute_ci',
        description=(
            'Compute 95% Wilson score confidence intervals for all primary '
            'Sentinel-Mesh evaluation metrics from raw CSV log files.'
        ),
    )
    parser.add_argument(
        '--csv-dir', default='logs', metavar='DIR',
        help=(
            'Directory containing benchmark CSV log files. '
            'Defaults to logs/.'
        ),
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = _parse_args()
    compute_and_print_all(csv_dir=args.csv_dir)
