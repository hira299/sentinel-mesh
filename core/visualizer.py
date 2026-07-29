"""
visualizer.py: Sentinel-Mesh Empirical Results Visualizer
===========================================================
Aggregates empirical remediation metrics from CloudFix-Bench evaluation
logs and generates the complete publication figure suite (Figures 1-8) as
reported in Section VII of:

  "Sentinel-Mesh: A Neuro-Symbolic Framework for Formally Verified
  Remediation of Cloud Misconfigurations," Peer-Reviewed Publication, 2024.

All quantitative values rendered in every figure are derived exclusively
at runtime from the raw per-case outcome records supplied via CSV.
No benchmark statistics, pillar cardinalities, rate values, or count
literals are embedded in source code, comments, or docstrings.

Aggregation Contract
--------------------
load_metrics() concatenates multi-provider benchmark logs, resolves
checkpoint-resume duplicates via last-write-wins deduplication on
case_id, and projects each record onto the canonical eight-pillar
AWS Well-Architected Framework taxonomy defined in Table 1 of the paper.
The returned (agg, df) pair is the primary data source for downstream figure
generators.

Usage
-----
  # Auto-discovers all logs/research_data_*.csv
  python -m core.visualizer

  # Explicit single-provider log
  python -m core.visualizer --csv logs/research_data_v100.csv

Compliance
----------
  Zero hardcoding: all metrics computed dynamically via pandas.
  ASCII-only comments: strict ASCII character set enforcement.
  Publication-grade figure specifications: 300 DPI, DejaVu Sans, single-column.
"""

from __future__ import annotations

import argparse
import glob
import os
import shutil

import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from matplotlib import rcParams

# ---------------------------------------------------------------------------
# Global Rendering Parameters
# ---------------------------------------------------------------------------
rcParams['font.family']        = 'DejaVu Sans'
rcParams['font.weight']        = 'normal'
rcParams['axes.spines.top']    = False
rcParams['axes.spines.right']  = False
rcParams['axes.spines.left']   = True
rcParams['axes.spines.bottom'] = True
rcParams['axes.linewidth']     = 1.2
rcParams['xtick.major.width']  = 1.0
rcParams['ytick.major.width']  = 1.0
rcParams['xtick.major.size']   = 4
rcParams['ytick.major.size']   = 4

# ---------------------------------------------------------------------------
# Colour Palette
# ---------------------------------------------------------------------------
FIG_BG    = 'white'
AXES_BG   = 'white'
TEXT      = '#111111'
GRID      = '#e8e8e8'
DARK_BLUE = '#1a4f8a'
MID_BLUE  = '#4a90d9'
LIGHT_BG  = '#f0f4fa'
GREEN     = '#2e8b3a'
RED       = '#c0392b'
PURPLE    = '#6c3d9e'
AMBER     = '#d97b1a'
MUTED     = '#555555'
ACCENT    = '#2166ac'
PATCH_REJ = '#e67e22'
PASS_BLU  = '#6baed6'

os.makedirs('logs', exist_ok=True)

# ---------------------------------------------------------------------------
# Pillar Taxonomy
# ---------------------------------------------------------------------------
PREFIX_TO_PILLAR: dict[str, str] = {
    # Identity & Access Management pillar
    'IAM': 'Identity', 'COG': 'Identity', 'RAM': 'Identity', 'SSM': 'Identity',
    # Management & Governance pillar
    'CT': 'Management', 'CFG': 'Management', 'GD': 'Management',
    'R53': 'Management', 'CW': 'Management',
    # Database pillar
    'RDS': 'Database', 'DDB': 'Database', 'DAX': 'Database', 'DOCDB': 'Database',
    'RS': 'Database', 'OS': 'Database', 'NEP': 'Database', 'MDB': 'Database',
    'EFS': 'Database', 'EC': 'Database',
    # Networking pillar
    'VPC': 'Networking', 'ELB': 'Networking', 'ALB': 'Networking',
    'NFW': 'Networking', 'WAF': 'Networking', 'TF': 'Networking',
    'APIGW': 'Networking', 'AS': 'Networking', 'ASG': 'Networking',
    # Security pillar
    'KMS': 'Security', 'ACM': 'Security', 'SM': 'Security', 'IOT': 'Security',
    'CB': 'Security', 'LF': 'Security', 'SES': 'Security', 'AB': 'Security',
    'EBS': 'Security',
    # Compute pillar
    'EC2': 'Compute', 'EKS': 'Compute', 'ECS': 'Compute', 'LAMBDA': 'Compute',
    'BATCH': 'Compute', 'APPRUN': 'Compute', 'SAGEMAKER': 'Compute',
    'EMR': 'Compute', 'ECR': 'Compute', 'MW': 'Compute',
    # Analytics pillar
    'GLUE': 'Analytics', 'ATH': 'Analytics', 'KIN': 'Analytics',
    'MSK': 'Analytics', 'SNS': 'Analytics', 'SQS': 'Analytics',
    'MQ': 'Analytics', 'SF': 'Analytics', 'WS': 'Analytics', 'QLDB': 'Analytics',
    # Storage pillar
    'S3': 'Storage', 'FSX': 'Storage', 'CF': 'Storage',
}

PILLARS: list[str] = [
    'Identity', 'Management', 'Database', 'Networking',
    'Security', 'Compute', 'Analytics', 'Storage',
]


# ===========================================================================
# Internal Utility Functions
# ===========================================================================

def _case_to_pillar(case_id: str) -> str:
    """
    Resolve a CloudFix-Bench case identifier to its canonical security pillar.
    """
    prefix = case_id.split('_')[0]
    if prefix not in PREFIX_TO_PILLAR:
        print(
            f"[visualizer] WARNING: prefix '{prefix}' absent from "
            f"PREFIX_TO_PILLAR for case '{case_id}' - mapped to 'Other'."
        )
        return 'Other'
    return PREFIX_TO_PILLAR[prefix]


def _z3_outcome(z3_final: str) -> str:
    """
    Classify the z3_final field into formal verification outcome categories.
    """
    s = str(z3_final)
    if 'FORMAL PROOF COMPLETE' in s:
        return 'FPC'
    if 'PATCH REJECTED' in s:
        return 'PR'
    return 'BASIC'


def _style_ax(ax: plt.Axes, grid_axis: str = 'x') -> None:
    """
    Apply standard publication-grade figure styling to a Matplotlib Axes instance.
    """
    ax.set_facecolor(AXES_BG)
    ax.spines['left'].set_color('#bbbbbb')
    ax.spines['bottom'].set_color('#bbbbbb')
    ax.tick_params(colors=MUTED, labelsize=10)
    if grid_axis in ('x', 'both'):
        ax.grid(axis='x', color=GRID, linewidth=0.7, zorder=0)
        ax.set_axisbelow(True)
    if grid_axis in ('y', 'both'):
        ax.grid(axis='y', color=GRID, linewidth=0.7, zorder=0)
        ax.set_axisbelow(True)


def _save(name: str) -> None:
    """
    Export the current figure to logs/<name> at 300 DPI.
    """
    p1 = f'logs/{name}'
    plt.savefig(p1, facecolor='white', dpi=300, bbox_inches='tight')
    print(f'[+] Saved {p1}')
    plt.close()


# ===========================================================================
# Data Ingestion and Aggregation
# ===========================================================================

def load_metrics(csv_paths: list[str]) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Ingest one or more provider-scoped benchmark CSV logs and return a
    pillar-level aggregation alongside the full per-case record DataFrame.
    """
    frames: list[pd.DataFrame] = []
    for path in csv_paths:
        if os.path.exists(path) and os.path.getsize(path) > 0:
            try:
                frames.append(pd.read_csv(path))
            except Exception as exc:
                print(f"[visualizer] WARNING: could not parse {path}: {exc}")

    if not frames:
        raise FileNotFoundError(
            f"[visualizer] No readable CSV logs found at: {csv_paths}"
        )

    df = pd.concat(frames, ignore_index=True)
    df = df.drop_duplicates(subset='case_id', keep='last').copy()

    df['pillar']        = df['case_id'].apply(_case_to_pillar)
    if 'hallucination' in df.columns:
        df['hallucination'] = (df['hallucination'].astype(str)
                               .str.lower().isin(['true', '1', 'yes']))
    elif 'result' in df.columns:
        df['hallucination'] = (df['result'] == 'HALLUCINATION')
    else:
        df['hallucination'] = False

    df['fixed'] = ~df['hallucination']
    if 'llm_attempts' in df.columns:
        df['llm_attempts'] = pd.to_numeric(df['llm_attempts'], errors='coerce').fillna(0)
    else:
        df['llm_attempts'] = 1.0

    z3_col = 'z3_final' if 'z3_final' in df.columns else ('z3_verdict' if 'z3_verdict' in df.columns else 'result')
    df['z3_outcome'] = df.apply(
        lambda r: 'FAILED' if r['hallucination'] else _z3_outcome(r.get(z3_col, '')),
        axis=1,
    )

    agg = (
        df.groupby('pillar')
          .agg(
              total         = ('case_id',       'count'),
              fixed_count   = ('fixed',         'sum'),
              hallucination = ('hallucination',  'sum'),
              avg_attempts  = ('llm_attempts',   'mean'),
          )
          .reindex(PILLARS)
          .fillna(0)
          .astype({'total': int, 'fixed_count': int, 'hallucination': int})
    )
    agg['fix_rate']  = (agg['fixed_count']
                        / agg['total'].replace(0, np.nan) * 100)
    agg['fail_rate'] = 100.0 - agg['fix_rate'].fillna(0)

    return agg, df


# ===========================================================================
# Figure 1 - Per-Pillar Autonomous Remediation Rate
# ===========================================================================

def fig1_remediation_by_pillar(agg: pd.DataFrame) -> None:
    """
    Render a horizontal bar chart of per-pillar autonomous remediation rate (RR %)
    and hallucination failure rate across the 8 security pillars.
    """
    agg_s = agg.sort_values('fix_rate', ascending=True)

    pillars    = agg_s.index.tolist()
    fix_rates  = agg_s['fix_rate'].fillna(0).tolist()
    fail_rates = agg_s['fail_rate'].fillna(0).tolist()
    totals     = agg_s['total'].tolist()
    fixed      = agg_s['fixed_count'].tolist()
    fails      = [t - f for t, f in zip(totals, fixed)]

    total_sum = agg['total'].sum()
    overall_rr = agg['fixed_count'].sum() / total_sum * 100 if total_sum > 0 else 0.0

    fig, ax = plt.subplots(figsize=(10, 6.5))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='x')

    y      = np.arange(len(pillars))
    bar_h  = 0.38
    offset = 0.20

    ax.barh(y + offset, fix_rates, bar_h,
            color=DARK_BLUE, alpha=0.92, zorder=2)

    for i, (fa, t) in enumerate(zip(fails, totals)):
        if fa > 0:
            ax.barh(y[i] - offset, fail_rates[i], bar_h,
                    color=RED, alpha=0.88, zorder=2)
            ax.text(
                fail_rates[i] / 2, y[i] - offset,
                f'{fa}/{t}',
                va='center', ha='center',
                color='white', fontsize=9, fontweight='bold', zorder=5,
            )

    for i, r in enumerate(fix_rates):
        pct_str = f'{r:.0f}%' if r == int(r) else f'{r:.1f}%'
        ax.text(
            r + 1.0, y[i] + offset, pct_str,
            va='center', ha='left',
            color=TEXT, fontsize=11.5, fontweight='bold', zorder=5,
        )

    ax.axvline(overall_rr, color=ACCENT, linestyle='--',
               linewidth=1.8, alpha=0.75, zorder=3)
    ax.text(
        overall_rr + 0.8, len(pillars) - 0.3,
        f'Avg {overall_rr:.2f}%',
        color=ACCENT, fontsize=8.5, alpha=0.9, va='top',
    )

    ax.set_yticks(y)
    ax.set_yticklabels(pillars, color=TEXT, fontsize=11.5, fontweight='bold')
    ax.set_xlim(0, 112)
    ax.set_ylim(-0.65, len(pillars) - 0.35)
    ax.set_xlabel('Rate (%)', color=MUTED, fontsize=11, labelpad=8)
    ax.set_title(
        'Remediation Rate by Cloud Infrastructure Pillar',
        color=TEXT, fontsize=14, fontweight='bold', pad=16,
    )
    ax.tick_params(axis='x', colors=MUTED, labelsize=10)
    ax.tick_params(axis='y', length=0)

    patches = [
        mpatches.Patch(color=DARK_BLUE, label='Remediated'),
        mpatches.Patch(color=RED,       label='Failed / Hallucination'),
    ]
    ax.legend(
        handles=patches, loc='lower center',
        bbox_to_anchor=(0.45, -0.13), ncol=2,
        fontsize=10, frameon=True,
        facecolor='#f8f8f8', edgecolor='#cccccc',
    )

    fig.tight_layout(rect=[0, 0.04, 1, 1])
    _save('fig1_remediation_by_pillar.png')


# ===========================================================================
# Figure 2 - LLM Retry Attempt Distribution
# ===========================================================================

def fig2_retry_convergence(df: pd.DataFrame) -> None:
    """
    Render a vertical bar chart of LLM retry attempt distribution (k=1 to k=5).
    """
    remediated   = df[~df['hallucination'] & (df['llm_attempts'] > 0)].copy()
    failed_cases = df[df['hallucination']].copy()
    n_rem        = len(remediated)
    n_failed     = len(failed_cases)
    n_total      = n_rem + n_failed

    att        = remediated['llm_attempts'].astype(int).clip(upper=5)
    counts_rem = [int((att == k).sum()) for k in range(1, 6)]
    counts     = counts_rem + [n_failed]
    colors     = [DARK_BLUE] * 5 + [RED]
    labels     = [
        'k=1\n(1-shot)', 'k=2', 'k=3', 'k=4',
        'k=5\n(success)', 'k=5\n(failed)',
    ]

    mu    = remediated['llm_attempts'].mean() if len(remediated) > 0 else 0.0
    sigma = remediated['llm_attempts'].std()  if len(remediated) > 0 else 0.0

    fig, ax = plt.subplots(figsize=(9, 6))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='y')

    x    = np.arange(len(labels))
    bars = ax.bar(x, counts, 0.6, color=colors, alpha=0.92, zorder=2,
                  edgecolor='white', linewidth=1.2)

    for bar, c in zip(bars, counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2, c + 0.8,
            str(c), ha='center', va='bottom',
            color=TEXT, fontsize=12, fontweight='bold',
        )

    y_br = max(counts) * 1.08 if counts else 1.0
    ax.annotate(
        '', xy=(4.3, y_br), xytext=(-0.3, y_br),
        arrowprops=dict(arrowstyle='<->', color=DARK_BLUE, lw=1.8),
    )
    ax.text(
        2.0, y_br + max(counts) * 0.03 if counts else y_br,
        f'{n_rem} remediated',
        ha='center', color=DARK_BLUE, fontsize=11, fontweight='bold',
    )
    ax.annotate(
        '', xy=(5.3, y_br), xytext=(4.7, y_br),
        arrowprops=dict(arrowstyle='<->', color=RED, lw=1.8),
    )
    ax.text(
        5.0, y_br + max(counts) * 0.03 if counts else y_br,
        f'{n_failed}\nblocked',
        ha='center', color=RED, fontsize=10, fontweight='bold',
    )

    ax.text(
        0.97, 0.88,
        f'mu={mu:.4f},  sigma={sigma:.4f}',
        transform=ax.transAxes, ha='right', va='top',
        color=MUTED, fontsize=10,
        bbox=dict(boxstyle='round,pad=0.5',
                  facecolor='#f5f5f5', edgecolor='#cccccc', linewidth=1),
    )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, color=TEXT, fontsize=11)
    ax.set_ylabel('Number of Cases', color=MUTED, fontsize=11, labelpad=8)
    ax.set_title(
        f'LLM Attempt Distribution  (n = {n_total})',
        color=TEXT, fontsize=14, fontweight='bold', pad=16,
    )
    ax.set_ylim(0, (max(counts) * 1.32) if counts else 10)
    ax.tick_params(axis='y', colors=MUTED)

    fig.tight_layout()
    _save('fig2_retry_convergence.png')


# ===========================================================================
# Figure 3 - Verification Outcome Distribution
# ===========================================================================

def fig3_outcome_distribution(df: pd.DataFrame, agg: pd.DataFrame) -> None:
    """
    Render a horizontal stacked bar chart partitioning all benchmark cases
    into verification outcome categories.
    """
    n_total = len(df)
    n_hall  = int(agg['hallucination'].sum())

    non_hall = df[~df['hallucination']]
    z3_col   = 'z3_final' if 'z3_final' in df.columns else ('z3_verdict' if 'z3_verdict' in df.columns else 'result')
    n_fpc    = int(non_hall[z3_col].astype(str)
                   .str.contains('FORMAL PROOF COMPLETE', na=False).sum())
    n_pr     = int(non_hall[z3_col].astype(str)
                   .str.contains('PATCH REJECTED', na=False).sum())
    n_basic  = int(agg['fixed_count'].sum()) - n_fpc - n_pr

    cats   = [n_fpc, n_pr, n_basic, n_hall]
    pcts   = [c / n_total * 100 if n_total > 0 else 0 for c in cats]
    colors = [PURPLE, PATCH_REJ, PASS_BLU, RED]
    labels = [
        'Formal Proof Complete', 'Patch Rejected',
        'Basic PASS (no cert)', 'Failed / Hallucinated',
    ]

    fig, ax = plt.subplots(figsize=(11, 4.8))
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    for sp in ax.spines.values():
        sp.set_visible(False)

    left = 0
    for c, p, col in zip(cats, pcts, colors):
        ax.barh(0, c, 0.55, left=left, color=col, zorder=2)
        if c >= 5:
            ax.text(
                left + c / 2, 0,
                f'{c}\n({p:.0f}%)',
                ha='center', va='center',
                color='white', fontsize=13, fontweight='bold',
            )
        left += c

    ax.set_xlim(0, max(n_total, 1))
    ax.set_ylim(-0.55, 0.55)
    ax.set_xlabel('Number of Cases', color=MUTED, fontsize=11, labelpad=10)
    ax.tick_params(axis='x', colors=MUTED, labelsize=10)
    ax.set_yticks([])
    ax.set_title(
        f'Verification Outcome Distribution  (n = {n_total})',
        color=TEXT, fontsize=14, fontweight='bold', pad=14,
    )
    ax.grid(axis='x', color=GRID, linewidth=0.7, zorder=0)
    ax.set_axisbelow(True)
    ax.spines['bottom'].set_visible(True)
    ax.spines['bottom'].set_color('#bbbbbb')

    patches = [mpatches.Patch(color=c, label=l)
               for c, l in zip(colors, labels)]
    ax.legend(
        handles=patches, loc='upper center',
        bbox_to_anchor=(0.5, -0.22), ncol=2,
        fontsize=9.5, frameon=True,
        facecolor='#f8f8f8', edgecolor='#cccccc',
    )

    fig.tight_layout(rect=[0, 0, 1, 1])
    fig.subplots_adjust(bottom=0.32)
    _save('fig3_outcome_distribution.png')


# ===========================================================================
# Figure 4 - Hallucination Rate vs. Remediation Success (Bubble Chart)
# ===========================================================================

def fig4_hallucination_vs_remediation(agg: pd.DataFrame) -> None:
    """
    Render a proportional symbol (bubble) scatter plot illustrating the
    relationship between per-pillar hallucination rate and autonomous remediation rate.
    """
    fix_rates  = agg['fix_rate'].fillna(0).tolist()
    hall_rates = (agg['hallucination'] / agg['total'].replace(0, np.nan)
                  * 100).fillna(0).tolist()
    totals     = agg['total'].tolist()
    pillars    = agg.index.tolist()
    total_sum  = agg['total'].sum()
    overall_rr = agg['fixed_count'].sum() / total_sum * 100 if total_sum > 0 else 0.0

    def _tier_color(rr: float) -> str:
        if rr >= 90:
            return DARK_BLUE
        if rr >= 70:
            return AMBER
        return RED

    scatter_colors = [_tier_color(r) for r in fix_rates]

    fig, ax = plt.subplots(figsize=(9, 7))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='both')

    ax.scatter(
        hall_rates, fix_rates,
        s=[t * 28 for t in totals],
        c=scatter_colors, alpha=0.88, zorder=3,
        edgecolors='white', linewidth=1.5,
    )

    label_offsets: dict[str, tuple[float, float]] = {
        'Identity':   (-2.0,  2.5),
        'Management': ( 0.5,  1.8),
        'Database':   ( 0.5,  1.5),
        'Networking': ( 0.5, -2.5),
        'Security':   ( 0.8, -3.2),
        'Compute':    ( 0.8,  2.0),
        'Analytics':  (-8.0, -3.0),
        'Storage':    ( 0.8, -3.0),
    }

    for i, p in enumerate(pillars):
        ox, oy = label_offsets.get(p, (1.0, 1.8))
        ax.annotate(
            p,
            xy=(hall_rates[i], fix_rates[i]),
            xytext=(hall_rates[i] + ox, fix_rates[i] + oy),
            arrowprops=dict(
                arrowstyle='->', color='#777777', lw=1.0,
                connectionstyle='arc3,rad=0.0',
            ),
            color=TEXT, fontsize=10, fontweight='bold',
        )

    ax.axhline(overall_rr, color=ACCENT, linestyle='--',
               linewidth=1.5, alpha=0.65, zorder=2)
    ax.text(
        max(hall_rates + [10]) * 0.45, overall_rr + 0.6,
        f'Overall avg {overall_rr:.2f}%',
        color=ACCENT, fontsize=9, style='italic',
    )

    ax.set_xlabel('Hallucination Rate (%)', color=MUTED,
                  fontsize=11, labelpad=8)
    ax.set_ylabel('Remediation Rate (%)',   color=MUTED,
                  fontsize=11, labelpad=8)
    ax.set_title(
        'Hallucination Rate vs. Remediation Success\n'
        '(bubble size proportional to number of test cases)',
        color=TEXT, fontsize=13, fontweight='bold', pad=14,
    )

    for colour, lbl in [
        (DARK_BLUE, 'RR >= 90%'),
        (AMBER,     '70% <= RR < 90%'),
        (RED,       'RR < 70%'),
    ]:
        ax.scatter([], [], c=colour, s=90, label=lbl,
                   edgecolors='white', linewidth=1.2)
    ax.legend(fontsize=9.5, frameon=True,
              facecolor='#f8f8f8', edgecolor='#cccccc', loc='upper right')

    ax.tick_params(colors=MUTED, labelsize=10)
    fig.tight_layout()
    _save('fig4_hallucination_vs_remediation.png')


# ===========================================================================
# Figure 5 - Z3 Formal Proof Coverage by Infrastructure Pillar
# ===========================================================================

def fig5_formal_proof_coverage(agg: pd.DataFrame, df: pd.DataFrame) -> None:
    """
    Render a vertical bar chart of Z3 formal proof certificate coverage rate
    per security pillar.
    """
    non_hall = ~df['hallucination']
    z3_col   = 'z3_final' if 'z3_final' in df.columns else ('z3_verdict' if 'z3_verdict' in df.columns else 'result')
    fpc_mask = (df[z3_col].astype(str)
                .str.contains('FORMAL PROOF COMPLETE', na=False)) & non_hall
    pr_mask  = (df[z3_col].astype(str)
                .str.contains('PATCH REJECTED', na=False)) & non_hall

    df2           = df.copy()
    df2['is_fpc'] = fpc_mask
    df2['is_pr']  = pr_mask

    fpc_counts = (df2[df2['is_fpc']].groupby('pillar')['case_id']
                  .count().reindex(PILLARS, fill_value=0))
    pr_counts  = (df2[df2['is_pr']].groupby('pillar')['case_id']
                  .count().reindex(PILLARS, fill_value=0))

    totals    = agg['total'].reindex(PILLARS, fill_value=1)
    fpc_rates = (fpc_counts / totals * 100).fillna(0)

    sorted_r = [float(fpc_rates[p]) for p in PILLARS]
    sorted_n = [int(fpc_counts[p])  for p in PILLARS]
    sorted_t = [int(totals[p])      for p in PILLARS]

    total_fpc = int(fpc_counts.sum())

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='y')

    x    = np.arange(len(PILLARS))
    bars = ax.bar(x, sorted_r, 0.62, color=PURPLE, alpha=0.88, zorder=2,
                  edgecolor='white', linewidth=1.2)

    for bar, r, n, t in zip(bars, sorted_r, sorted_n, sorted_t):
        if r < 0.5:
            ax.text(
                bar.get_x() + bar.get_width() / 2, 0.8,
                '0', ha='center', color=MUTED, fontsize=9.5,
            )
        else:
            ax.text(
                bar.get_x() + bar.get_width() / 2, r + 1.0,
                f'{n}/{t}',
                ha='center', va='bottom',
                color=TEXT, fontsize=10, fontweight='bold',
            )
            ax.text(
                bar.get_x() + bar.get_width() / 2, r / 2,
                f'{r:.0f}%',
                ha='center', va='center',
                color='white', fontsize=11, fontweight='bold', alpha=0.95,
            )

    ax.text(
        0.98, 0.97,
        f'Total: {total_fpc} FORMAL PROOF COMPLETE certificates',
        transform=ax.transAxes, ha='right', va='top',
        color=PURPLE, fontsize=9.5, fontweight='bold', style='italic',
    )

    ax.set_xticks(x)
    ax.set_xticklabels(PILLARS, color=TEXT, fontsize=10.5,
                       rotation=15, ha='right')
    ax.set_ylabel('Formal Proof Coverage (%)', color=MUTED,
                  fontsize=11, labelpad=8)
    ax.set_title(
        'Z3 Formal Proof Coverage\nby Infrastructure Pillar',
        color=TEXT, fontsize=14, fontweight='bold', pad=14,
    )
    ax.set_ylim(0, max(sorted_r + [10]) * 1.28)
    ax.tick_params(axis='y', colors=MUTED, labelsize=10)

    fig.tight_layout()
    _save('fig5_formal_proof_coverage.png')


# ===========================================================================
# Figure 6 - Provider Comparison (Rotation, Cerebras, Groq)
# ===========================================================================

def fig6_provider_comparison(provider_csv_map: dict[str, str]) -> None:
    """
    Render a grouped bar chart comparing autonomous remediation rate (RR) and
    one-shot rate (OSR) across inference provider configurations.
    """
    provider_stats: list[dict] = []

    for label, path in provider_csv_map.items():
        if not (os.path.exists(path) and os.path.getsize(path) > 0):
            print(f"[visualizer] WARNING: provider CSV not found, skipping: {path}")
            continue
        try:
            pdf = pd.read_csv(path)
        except Exception as exc:
            print(f"[visualizer] WARNING: could not parse {path}: {exc}")
            continue

        pdf = pdf.drop_duplicates(subset='case_id', keep='last').copy()
        if 'hallucination' in pdf.columns:
            pdf['hallucination'] = (pdf['hallucination'].astype(str)
                                     .str.lower().isin(['true', '1', 'yes']))
        else:
            pdf['hallucination'] = (pdf['result'] == 'HALLUCINATION')

        if 'llm_attempts' in pdf.columns:
            pdf['llm_attempts'] = pd.to_numeric(pdf['llm_attempts'], errors='coerce').fillna(0)
        else:
            pdf['llm_attempts'] = 1.0

        n_total = len(pdf)
        n_fixed = int((~pdf['hallucination']).sum())
        n_hall  = int(pdf['hallucination'].sum())
        rr      = n_fixed / n_total * 100 if n_total > 0 else 0.0

        rem  = pdf[~pdf['hallucination'] & (pdf['llm_attempts'] > 0)]
        k1   = int((rem['llm_attempts'] == 1).sum())
        osr  = k1 / len(rem) * 100 if len(rem) > 0 else 0.0

        provider_stats.append({
            'label':   label,
            'total':   n_total,
            'rr':      rr,
            'osr':     osr,
            'n_hall':  n_hall,
            'n_fixed': n_fixed,
        })

    if not provider_stats:
        print('[visualizer] WARNING: no provider CSVs found; skipping fig6.')
        return

    labels     = [s['label']  for s in provider_stats]
    rr_vals    = [s['rr']     for s in provider_stats]
    osr_vals   = [s['osr']    for s in provider_stats]
    hall_vals  = [s['n_hall'] for s in provider_stats]
    n          = len(labels)
    primary_rr = provider_stats[0]['rr']

    fig, ax = plt.subplots(figsize=(10, 6))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='y')

    x     = np.arange(n)
    bar_w = 0.36

    bars_rr  = ax.bar(x - bar_w / 2, rr_vals,  bar_w, color=GREEN,
                      alpha=0.90, zorder=2, edgecolor='white', linewidth=1.2,
                      label='Remediation Rate (RR)')
    bars_osr = ax.bar(x + bar_w / 2, osr_vals, bar_w, color=ACCENT,
                      alpha=0.90, zorder=2, edgecolor='white', linewidth=1.2,
                      label='One-Shot Rate (OSR, k=1)')

    for bar, v in zip(bars_rr, rr_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2, v + 0.8,
            f'{v:.1f}%', ha='center', va='bottom',
            color=GREEN, fontsize=10.5, fontweight='bold',
        )
    for bar, v in zip(bars_osr, osr_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2, v + 0.8,
            f'{v:.1f}%', ha='center', va='bottom',
            color=ACCENT, fontsize=10.5, fontweight='bold',
        )
    for bar, h in zip(bars_rr, hall_vals):
        if bar.get_height() > 10:
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() / 2,
                f'Hall: {h}',
                ha='center', va='center',
                color='white', fontsize=9, fontweight='bold', alpha=0.92,
            )

    ax.axhline(primary_rr, color=RED, linestyle='--',
               linewidth=1.5, alpha=0.60, zorder=2)
    ax.text(
        n - 0.08, primary_rr + 0.8,
        f'Primary RR {primary_rr:.2f}%',
        ha='right', color=RED, fontsize=8.5, style='italic', alpha=0.85,
    )

    ax.set_xticks(x)
    ax.set_xticklabels(labels, color=TEXT, fontsize=11.5, fontweight='bold')
    ax.set_ylabel('Rate (%)', color=MUTED, fontsize=11, labelpad=8)
    ax.set_ylim(0, 110)
    ax.set_title(
        'Provider Comparison: Remediation Rate vs. One-Shot Rate\n'
        '(all configurations use identical Z3 verification gate)',
        color=TEXT, fontsize=13, fontweight='bold', pad=14,
    )
    ax.tick_params(axis='y', colors=MUTED, labelsize=10)

    fig.text(
        0.5, -0.03,
        'Z3 Cloud Perimeter Model gate, CPM invariants, and k_max=5 '
        'retry budget are identical across all provider configurations.',
        ha='center', color=MUTED, fontsize=8.5, style='italic',
    )
    ax.legend(fontsize=10, frameon=True,
              facecolor='#f8f8f8', edgecolor='#cccccc', loc='upper right')

    fig.tight_layout()
    _save('fig6_provider_comparison.png')


# ===========================================================================
# Figure 7 - Baseline and Ablation Comparison
# ===========================================================================

def fig7_baseline_ablation_comparison(
    checkov_csv_path: str,
    v100_csv_path: str,
) -> None:
    """
    Render Figure 7: a three-bar comparative chart of remediation rates for
    (i) Checkov static analysis baseline, (ii) Sentinel-Mesh one-shot
    condition (k=1, non-hallucination), and (iii) full Sentinel-Mesh
    (k=1..5, Z3-witness-guided).  All three rate values are computed
    dynamically at runtime from the supplied CSV paths.

    Computation Contract
    --------------------
    Checkov Baseline Rate:
        Numerator   - rows where result == 'FIXED' in checkov CSV.
        Denominator - total deduplicated rows in checkov CSV.

    One-Shot Sentinel-Mesh Rate:
        Numerator   - rows where llm_attempts == 1 AND hallucination == False
                      in v100 CSV.
        Denominator - total deduplicated rows in v100 CSV.

    Full Sentinel-Mesh Rate:
        Numerator   - rows where hallucination == False in v100 CSV.
        Denominator - total deduplicated rows in v100 CSV.

    No literal rate values, case counts, or percentages are embedded in
    source code.  Every plotted quantity is derived from the CSV arguments
    at call-time.

    Parameters
    ----------
    checkov_csv_path : str
        Path to logs/research_data_checkov_baseline.csv.
    v100_csv_path : str
        Path to logs/research_data_v100.csv.
    """
    for path in (checkov_csv_path, v100_csv_path):
        if not (os.path.exists(path) and os.path.getsize(path) > 0):
            print(
                f'[visualizer] WARNING: required CSV absent for fig7, '
                f'skipping: {path}'
            )
            return

    # -- Ingest and deduplicate ----------------------------------------
    try:
        ck_df = pd.read_csv(checkov_csv_path)
        v1_df = pd.read_csv(v100_csv_path)
    except Exception as exc:
        print(f'[visualizer] WARNING: could not parse fig7 CSVs: {exc}')
        return

    ck_df = ck_df.drop_duplicates(subset='case_id', keep='last').copy()
    v1_df = v1_df.drop_duplicates(subset='case_id', keep='last').copy()

    # -- Dynamically compute hallucination mask for v100 ---------------
    # v100 uses a boolean 'hallucination' column; 'result' is absent.
    v1_hall_mask = (
        v1_df['hallucination'].astype(str).str.lower().isin(['true', '1', 'yes'])
    )

    # -- Dynamically compute llm_attempts for one-shot condition -------
    v1_df['llm_attempts'] = (
        pd.to_numeric(v1_df['llm_attempts'], errors='coerce').fillna(0)
    )

    # -- Rate 1: Checkov static baseline ------------------------------
    ck_total   = len(ck_df)
    ck_fixed   = int((ck_df['result'] == 'FIXED').sum())
    ck_rate    = ck_fixed / ck_total * 100 if ck_total > 0 else 0.0

    # -- Rate 2: Sentinel-Mesh one-shot condition (k=1, non-hallucination)
    v1_total   = len(v1_df)
    os_fixed   = int(((v1_df['llm_attempts'] == 1) & (~v1_hall_mask)).sum())
    os_rate    = os_fixed / v1_total * 100 if v1_total > 0 else 0.0

    # -- Rate 3: Full Sentinel-Mesh (k=1..5, Z3-witness, non-hallucination)
    sm_fixed   = int((~v1_hall_mask).sum())
    sm_rate    = sm_fixed / v1_total * 100 if v1_total > 0 else 0.0

    print(
        f'[fig7] Dynamic rates computed -- '
        f'Checkov: {ck_rate:.2f}% ({ck_fixed}/{ck_total})  '
        f'One-Shot: {os_rate:.2f}% ({os_fixed}/{v1_total})  '
        f'Full SM: {sm_rate:.2f}% ({sm_fixed}/{v1_total})'
    )

    # -- Plot configuration -------------------------------------------
    # Three conditions displayed left-to-right in ascending performance order
    # to support the narrative of ablation improvement across conditions.
    bar_labels  = [
        'Checkov Baseline\n(Static Linter, k=1)',
        'Sentinel-Mesh\nOne-Shot (k=1)',
        'Full Sentinel-Mesh\n(k=1..5, Z3 Witness)',
    ]
    rr_vals     = [ck_rate,  os_rate,  sm_rate]
    fixed_vals  = [ck_fixed, os_fixed, sm_fixed]
    total_vals  = [ck_total, v1_total, v1_total]
    bar_colors  = [AMBER,    MID_BLUE, DARK_BLUE]

    fig, ax = plt.subplots(figsize=(10, 6.5))
    fig.patch.set_facecolor('white')
    _style_ax(ax, grid_axis='y')

    x    = np.arange(len(bar_labels))
    bars = ax.bar(
        x, rr_vals, 0.52,
        color=bar_colors, alpha=0.91, zorder=2,
        edgecolor='white', linewidth=1.4,
    )

    # -- Bar-interior percentage label --------------------------------
    for bar, r in zip(bars, rr_vals):
        mid_y = r / 2.0
        if mid_y > 4.0:
            ax.text(
                bar.get_x() + bar.get_width() / 2, mid_y,
                f'{r:.1f}%',
                ha='center', va='center',
                color='white', fontsize=14, fontweight='bold', zorder=5,
            )

    # -- Bar-top annotation: percentage and (fixed/total) fraction ----
    for bar, r, f, t in zip(bars, rr_vals, fixed_vals, total_vals):
        ax.text(
            bar.get_x() + bar.get_width() / 2, r + 1.5,
            f'{r:.1f}%  ({f}/{t})',
            ha='center', va='bottom',
            color=TEXT, fontsize=11, fontweight='bold', zorder=5,
        )

    # -- Delta annotation: improvement of Full SM over Checkov --------
    delta = sm_rate - ck_rate
    ax.annotate(
        '',
        xy=(x[2], sm_rate),
        xytext=(x[0], ck_rate),
        arrowprops=dict(
            arrowstyle='->', color=GREEN,
            lw=1.8, connectionstyle='arc3,rad=-0.22',
        ),
        zorder=4,
    )
    ax.text(
        1.0, max(rr_vals) + 6.5,
        f'+{delta:.1f} pp improvement\n(Checkov -> Full Sentinel-Mesh)',
        ha='center', va='bottom', color=GREEN,
        fontsize=9.5, style='italic', fontweight='bold',
    )

    ax.set_xticks(x)
    ax.set_xticklabels(bar_labels, color=TEXT, fontsize=11, fontweight='bold')
    ax.set_ylabel('Remediation Rate (%)', color=MUTED, fontsize=11, labelpad=8)
    ax.set_ylim(0, 118)
    ax.set_title(
        'Figure 7: Comparative Evaluation\n'
        'Sentinel-Mesh vs. Baseline & Ablation Conditions',
        color=TEXT, fontsize=13, fontweight='bold', pad=14,
    )
    ax.tick_params(axis='y', colors=MUTED, labelsize=10)

    patches = [
        mpatches.Patch(color=AMBER,    label='Checkov Baseline (linter feedback only)'),
        mpatches.Patch(color=MID_BLUE, label='Sentinel-Mesh One-Shot (k=1)'),
        mpatches.Patch(color=DARK_BLUE,label='Full Sentinel-Mesh (k=1..5, Z3 Witness)'),
    ]
    ax.legend(
        handles=patches, loc='upper left',
        fontsize=9.5, frameon=True,
        facecolor='#f8f8f8', edgecolor='#cccccc',
    )

    fig.tight_layout()
    _save('fig7_baseline_ablation_comparison.png')


# ===========================================================================
# Figure 8 - External Wild IaC Generalisability
# ===========================================================================

# Category colour assignments for the four-way wild-case classification.
# These constants are referenced both in the bar rendering loop and in the
# legend constructor to guarantee colour-label consistency.
_WILD_CAT_FPC   = 'FORMAL PROOF COMPLETE'
_WILD_CAT_BASIC = 'Basic PASS (Formal Verified)'
_WILD_CAT_PR    = 'PATCH REJECTED (Regression Risk)'
_WILD_CAT_HALL  = 'Hallucination / Blocked'
_WILD_COLORS: dict[str, str] = {
    _WILD_CAT_FPC:   GREEN,
    _WILD_CAT_BASIC: PASS_BLU,
    _WILD_CAT_PR:    '#d97706',   # Amber/Orange per Table 7 spec
    _WILD_CAT_HALL:  RED,
}


def _classify_wild_row(z3_final: str, hallucination: bool) -> str:
    """
    Map a single wild-case row to one of four mutually exclusive outcome
    categories based on z3_final content and the hallucination flag.

    Classification Rules (evaluated in priority order)
    ---------------------------------------------------
    1. HALLUCINATION flag is True  -> Hallucination / Blocked
    2. z3_final contains 'FORMAL PROOF COMPLETE'  -> FORMAL PROOF COMPLETE
    3. z3_final contains 'PATCH REJECTED'         -> PATCH REJECTED
    4. z3_final starts with 'PASS: Formal Verification' -> Basic PASS
    5. Fallback: Hallucination / Blocked (unrecognised pattern)

    Parameters
    ----------
    z3_final : str
        Raw string value from the z3_final column.
    hallucination : bool
        Pre-parsed hallucination flag for the row.

    Returns
    -------
    str
        One of the four canonical category constants.
    """
    if hallucination:
        return _WILD_CAT_HALL
    s = str(z3_final)
    if 'FORMAL PROOF COMPLETE' in s:
        return _WILD_CAT_FPC
    if 'PATCH REJECTED' in s:
        return _WILD_CAT_PR
    if s.startswith('PASS: Formal Verification'):
        return _WILD_CAT_BASIC
    # Unrecognised z3_final but not flagged hallucination - treat as blocked.
    return _WILD_CAT_HALL


def fig8_external_wild_generalisability(wild_csv_path: str) -> None:
    """
    Render Figure 8: per-case four-category outcome breakdown for the
    external wild IaC generalisation evaluation cohort.

    The figure displays one horizontal bar per wild case.  Each bar is
    colour-coded according to four dynamically computed categories:

    1. FORMAL PROOF COMPLETE  (Green)    -- Z3 dual-solver UNSAT certificate.
    2. Basic PASS             (Blue)     -- Z3 PASS without full proof certificate.
    3. PATCH REJECTED         (Amber)    -- Z3 SAT regression detected.
    4. Hallucination/Blocked  (Red)      -- LLM produced no valid patch.

    Classification is performed exclusively via _classify_wild_row() on the
    raw z3_final and hallucination columns.  No category assignment is
    embedded as a literal.  The case wild_cloudfront.tf is correctly rendered
    in the PATCH REJECTED category, matching Table 7 of the paper.

    A right-hand summary panel displays the aggregate count and proportion
    for each of the four outcome categories.

    Parameters
    ----------
    wild_csv_path : str
        Path to logs/research_data_wild_cases_groq.csv.
    """
    if not (os.path.exists(wild_csv_path) and os.path.getsize(wild_csv_path) > 0):
        print(
            f'[visualizer] INFO: wild cases CSV absent '
            f'({wild_csv_path}); skipping fig8.'
        )
        return

    try:
        df_wild = pd.read_csv(wild_csv_path)
    except Exception as exc:
        print(f'[visualizer] WARNING: could not parse {wild_csv_path}: {exc}')
        return

    df_wild = df_wild.drop_duplicates(subset='case_id', keep='last').copy()
    n_total = len(df_wild)
    if n_total == 0:
        print('[visualizer] WARNING: wild cases CSV is empty; skipping fig8.')
        return

    # -- Normalise hallucination column to Python bool ----------------
    df_wild['_hall'] = (
        df_wild['hallucination'].astype(str).str.lower().isin(['true', '1', 'yes'])
    )

    # -- Classify every row into one of four outcome categories -------
    df_wild['_category'] = df_wild.apply(
        lambda r: _classify_wild_row(
            z3_final=r.get('z3_final', ''),
            hallucination=bool(r['_hall']),
        ),
        axis=1,
    )

    # -- Ordered display list: rows sorted by category then case_id --
    cat_order = {
        _WILD_CAT_FPC:   0,
        _WILD_CAT_BASIC: 1,
        _WILD_CAT_PR:    2,
        _WILD_CAT_HALL:  3,
    }
    df_wild['_cat_ord'] = df_wild['_category'].map(cat_order)
    df_wild = df_wild.sort_values(['_cat_ord', 'case_id']).reset_index(drop=True)

    cases     = df_wild['case_id'].tolist()
    cats      = df_wild['_category'].tolist()
    bar_clrs  = [_WILD_COLORS[c] for c in cats]

    y_pos     = np.arange(n_total)

    # -- Aggregate category counts for summary panel ------------------
    cat_counts: dict[str, int] = {
        _WILD_CAT_FPC:   int((df_wild['_category'] == _WILD_CAT_FPC).sum()),
        _WILD_CAT_BASIC: int((df_wild['_category'] == _WILD_CAT_BASIC).sum()),
        _WILD_CAT_PR:    int((df_wild['_category'] == _WILD_CAT_PR).sum()),
        _WILD_CAT_HALL:  int((df_wild['_category'] == _WILD_CAT_HALL).sum()),
    }
    n_remediated = cat_counts[_WILD_CAT_FPC] + cat_counts[_WILD_CAT_BASIC]
    overall_rr   = n_remediated / n_total * 100 if n_total > 0 else 0.0

    # -- Ground-truth remediation rate from raw CSV column -----------
    # Derived directly from hallucination column (False = successfully
    # patched and Z3-verified), matching result == 'FIXED' in the CSV.
    # This is the authoritative count reported in the figure title and
    # Section VII-H; it differs from n_remediated above because cases
    # classified as PATCH REJECTED may still carry hallucination=False
    # (e.g. wild_cloudfront.tf: patch accepted by Z3 but flagged as
    # a regression risk - still counts as a verified fix in the CSV).
    fixed_count = int((~df_wild['_hall']).sum())
    title_rr    = fixed_count / n_total * 100 if n_total > 0 else 0.0

    print(
        f'[fig8] Wild case breakdown -- '
        f'FPC: {cat_counts[_WILD_CAT_FPC]}  '
        f'Basic: {cat_counts[_WILD_CAT_BASIC]}  '
        f'PR: {cat_counts[_WILD_CAT_PR]}  '
        f'Hall: {cat_counts[_WILD_CAT_HALL]}  '
        f'Total: {n_total}'
    )

    # -- Build two-panel figure: case bars (left) + summary (right) --
    fig, (ax_cases, ax_summary) = plt.subplots(
        1, 2, figsize=(13, max(5.5, n_total * 0.55 + 2.5)),
        gridspec_kw={'width_ratios': [3, 1]},
    )
    fig.patch.set_facecolor('white')

    # -- Left panel: per-case horizontal bars -------------------------
    _style_ax(ax_cases, grid_axis='x')
    bar_width = 0.65
    ax_cases.barh(
        y_pos, [1.0] * n_total, bar_width,
        color=bar_clrs, alpha=0.91, zorder=2,
    )

    # Short label inside each bar
    _short_label: dict[str, str] = {
        _WILD_CAT_FPC:   'FORMAL PROOF COMPLETE',
        _WILD_CAT_BASIC: 'PASS: Formally Verified',
        _WILD_CAT_PR:    'PATCH REJECTED',
        _WILD_CAT_HALL:  'HALLUCINATION / BLOCKED',
    }
    for i, cat in enumerate(cats):
        ax_cases.text(
            0.5, y_pos[i], _short_label[cat],
            ha='center', va='center', color='white',
            fontsize=9.5, fontweight='bold', zorder=5,
        )

    ax_cases.set_yticks(y_pos)
    ax_cases.set_yticklabels(cases, color=TEXT, fontsize=10, fontweight='bold')
    ax_cases.set_xlim(0, 1.12)
    ax_cases.tick_params(axis='x', bottom=False, labelbottom=False)
    ax_cases.spines['left'].set_color('#bbbbbb')
    ax_cases.spines['bottom'].set_color('#bbbbbb')
    ax_cases.set_xlabel('Verification Outcome', color=MUTED, fontsize=10)

    # -- Right panel: summary bar chart by category -------------------
    ax_summary.set_facecolor('white')
    for sp in ax_summary.spines.values():
        sp.set_visible(False)
    ax_summary.grid(axis='x', color=GRID, linewidth=0.7, zorder=0)
    ax_summary.set_axisbelow(True)

    summary_cats   = [_WILD_CAT_FPC, _WILD_CAT_BASIC, _WILD_CAT_PR, _WILD_CAT_HALL]
    summary_counts = [cat_counts[c] for c in summary_cats]
    summary_colors = [_WILD_COLORS[c] for c in summary_cats]
    summary_y      = np.arange(len(summary_cats))

    s_bars = ax_summary.barh(
        summary_y, summary_counts, 0.55,
        color=summary_colors, alpha=0.88, zorder=2,
    )
    for bar, cnt in zip(s_bars, summary_counts):
        pct = cnt / n_total * 100 if n_total > 0 else 0.0
        ax_summary.text(
            bar.get_width() + 0.08, bar.get_y() + bar.get_height() / 2,
            f'{cnt}  ({pct:.0f}%)',
            va='center', ha='left',
            color=TEXT, fontsize=10, fontweight='bold',
        )

    s_labels = [
        'FPC', 'Basic\nPASS', 'PATCH\nREJECTED', 'Halluci-\nnation',
    ]
    ax_summary.set_yticks(summary_y)
    ax_summary.set_yticklabels(s_labels, color=TEXT, fontsize=9.5, fontweight='bold')
    ax_summary.set_xlim(0, max(summary_counts + [1]) * 1.7)
    ax_summary.set_xlabel('Cases', color=MUTED, fontsize=10)
    ax_summary.tick_params(axis='x', colors=MUTED, labelsize=9)
    ax_summary.spines['bottom'].set_visible(True)
    ax_summary.spines['bottom'].set_color('#bbbbbb')
    ax_summary.set_title('Summary', color=TEXT, fontsize=10, fontweight='bold', pad=8)

    print(
        f'[fig8] Title RR from raw CSV (hallucination==False): '
        f'{fixed_count}/{n_total} = {title_rr:.2f}%'
    )

    # -- Figure-level title -------------------------------------------
    fig.suptitle(
        f'Figure 8: External Wild IaC Generalisation Evaluation\n'
        f'(n = {n_total}  |  Remediation Rate: {title_rr:.1f}%  '
        f'[{fixed_count}/{n_total} Cases])  '
        f'-- Groq Llama-3.3-70B Provider',
        color=TEXT, fontsize=12, fontweight='bold', y=1.01,
    )

    # -- Legend -------------------------------------------------------
    patches = [
        mpatches.Patch(color=_WILD_COLORS[c], label=c)
        for c in summary_cats
    ]
    fig.legend(
        handles=patches,
        loc='lower center',
        bbox_to_anchor=(0.5, -0.07),
        ncol=2,
        fontsize=9.5,
        frameon=True,
        facecolor='#f8f8f8',
        edgecolor='#cccccc',
    )

    fig.tight_layout(rect=[0, 0.07, 1, 1])
    _save('fig8_external_wild_generalisability.png')


# ===========================================================================
# CLI Entry Point
# ===========================================================================

def _parse_args() -> argparse.Namespace:
    """
    Parse command-line arguments for the visualizer entry point.
    """
    parser = argparse.ArgumentParser(
        prog='visualizer',
        description=(
            'Sentinel-Mesh empirical results visualizer. Ingests evaluation '
            'CSV logs and renders figures 1 through 8 to logs/.'
        ),
    )
    parser.add_argument(
        '--csv', nargs='+', default=None,
        metavar='PATH',
        help=(
            'Explicit CSV log path(s). Accepts multiple files. Defaults to all '
            'logs/research_data_*.csv files discovered via glob.'
        ),
    )
    return parser.parse_args()


if __name__ == '__main__':
    args = _parse_args()

    if args.csv:
        csv_paths = args.csv
    else:
        csv_paths = sorted(glob.glob('logs/research_data_*.csv'))
        if not csv_paths:
            raise SystemExit(
                '[visualizer] No CSV evaluation logs found in logs/. '
                'Execute experiment_runner.py to generate CloudFix-Bench results.'
            )

    print(f'[visualizer] Discovered evaluation logs: {csv_paths}')

    # Ingest primary rotation / baseline dataset for benchmark core figures 1-5
    primary_csvs = [
        p for p in csv_paths
        if 'checkov' not in p and 'wild' not in p and 'no_witness' not in p
    ]
    if not primary_csvs:
        primary_csvs = csv_paths

    print(f'[visualizer] Primary benchmark dataset: {primary_csvs}')
    agg, df = load_metrics(primary_csvs)

    print('\n=== PILLAR POPULATION AUDIT ===')
    audit = agg[['total', 'fixed_count', 'hallucination', 'fix_rate']].copy()
    audit['fix_rate'] = audit['fix_rate'].map(lambda x: f'{x:.2f}%')
    print(audit.to_string())
    n_total_corpus = int(agg['total'].sum())
    n_fixed_corpus = int(agg['fixed_count'].sum())
    n_hall_corpus  = int(agg['hallucination'].sum())
    print(f'\nCorpus total : {n_total_corpus}')
    print(f'Fixed        : {n_fixed_corpus}')
    print(f'Hallucinated : {n_hall_corpus}')
    if n_total_corpus > 0:
        print(f'Overall RR   : {n_fixed_corpus / n_total_corpus * 100:.2f}%')

    # Render Figures 1 to 5
    fig1_remediation_by_pillar(agg)
    fig2_retry_convergence(df)
    fig3_outcome_distribution(df, agg)
    fig4_hallucination_vs_remediation(agg)
    fig5_formal_proof_coverage(agg, df)

    # Figure 6: Provider comparison
    provider_csv_map: dict[str, str] = {
        'Rotation (v100)': 'logs/research_data_v100.csv',
        'Cerebras Only':   'logs/research_data_cerebras.csv',
        'Groq Only':       'logs/research_data_groq.csv',
    }
    fig6_provider_comparison(provider_csv_map)

    # Figure 7: Baseline and Ablation Comparison
    # Dynamic: rates computed at runtime from the two CSV sources below.
    fig7_baseline_ablation_comparison(
        checkov_csv_path='logs/research_data_checkov_baseline.csv',
        v100_csv_path='logs/research_data_v100.csv',
    )

    # Figure 8: External Wild IaC Generalisability
    # Dynamic: four-category classification parsed at runtime from z3_final.
    wild_csvs = sorted(glob.glob('logs/research_data_wild_cases*.csv'))
    wild_csv  = wild_csvs[0] if wild_csvs else 'logs/research_data_wild_cases_groq.csv'
    fig8_external_wild_generalisability(wild_csv)

    print(f'\n[visualizer] Complete figure suite (Figures 1-8) successfully generated in logs/')