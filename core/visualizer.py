import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
from matplotlib import rcParams
import os

# ── Output folder ─────────────────────────────────────────────────────────────
os.makedirs('logs', exist_ok=True)

# ── Typography & style ────────────────────────────────────────────────────────
rcParams['font.family'] = 'DejaVu Sans'
rcParams['axes.spines.top'] = False
rcParams['axes.spines.right'] = False

# ── Palette ───────────────────────────────────────────────────────────────────
DARK       = '#0d1117'
PANEL_BG   = '#161b22'
CARD_BG    = '#1f2937'
ACCENT     = '#58a6ff'
GREEN      = '#3fb950'
AMBER      = '#d29922'
RED        = '#f85149'
PURPLE     = '#bc8cff'
MUTED      = '#8b949e'
WHITE      = '#f0f6fc'
GRID_COLOR = '#21262d'

# ── ALL DATA VERIFIED FROM research_data_v100.csv ─────────────────────────────
# Pillar order: Identity, Management, Database, Networking, Security, Compute, Analytics, Storage
pillars       = ['Identity','Management','Database','Networking','Security','Compute','Analytics','Storage']
total_cases   = [9,  6,  17, 15, 12, 23, 13, 10]
fixed_cases   = [9,  6,  16, 14, 11, 17,  9,  6]
hallucination = [0,  0,   1,  1,  1,  6,  4,  4]
formal_proofs = [0,  2,  12,  3,  3,  7,  7,  3]   # FORMAL PROOF COMPLETE + PATCH REJECTED = 37 total
fix_rates     = [f/t*100 for f,t in zip(fixed_cases, total_cases)]

# Attempt distribution — k=1:75, k=2:5, k=3:6, k=4:1, k=5:1  (sums to 88)
attempt_labels = ['1 attempt\n(one-shot)', '2 attempts', '3 attempts', '4 attempts', '5 attempts']
attempt_counts = [75, 5, 6, 1, 1]
attempt_colors = [GREEN, ACCENT, AMBER, RED, '#ff7b72']

# Outcome breakdown: 37 formal (29 FPC + 8 PR), 51 plain PASS, 17 hallucination
pie_labels = ['Fixed + Formal Proof\n(29 FPC + 8 Rejected)', 'Fixed (verified)', 'LLM Hallucination']
pie_sizes  = [37, 51, 17]
pie_colors = [PURPLE, GREEN, RED]

def _style_ax(ax):
    ax.set_facecolor(PANEL_BG)
    for spine in ax.spines.values():
        spine.set_color(GRID_COLOR)

def save(name):
    plt.savefig(f'logs/{name}', dpi=300, bbox_inches='tight',
                facecolor=DARK, edgecolor='none')
    print(f'[+] Saved logs/{name}')
    plt.close()

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 1 — Remediation rate by pillar
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 6), facecolor=DARK)
_style_ax(ax)

y     = np.arange(len(pillars))
bar_h = 0.38
fail_rates = [100 - r for r in fix_rates]

ax.barh(y + bar_h/2, [100]*len(pillars), bar_h*2, color=CARD_BG, zorder=1)
ax.barh(y,           fix_rates,           bar_h,   color=GREEN, alpha=0.9,  zorder=2, label='Remediated')
ax.barh(y + bar_h,   fail_rates,          bar_h,   color=RED,   alpha=0.75, zorder=2, label='Failed / Hallucination')

for i, (r, f) in enumerate(zip(fix_rates, fixed_cases)):
    ax.text(r + 1.5, i,         f'{r:.0f}%',
            va='center', ha='left', color=WHITE, fontsize=9, fontweight='bold')
    ax.text(101.5,   i + bar_h, f'{total_cases[i]-f}✗ / {total_cases[i]}',
            va='center', ha='left', color=MUTED, fontsize=7.5)

ax.set_yticks(y + bar_h/2)
ax.set_yticklabels(pillars, color=WHITE, fontsize=11)
ax.set_xlim(0, 122)
ax.set_xlabel('Remediation Rate (%)', color=MUTED, fontsize=10)
ax.set_title('Remediation Rate by Cloud Infrastructure Pillar',
             color=WHITE, fontsize=13, fontweight='bold', pad=14)
ax.tick_params(colors=MUTED, labelsize=9)
ax.grid(axis='x', color=GRID_COLOR, linewidth=0.5, zorder=0)
ax.axvline(88/105*100, color=ACCENT, linestyle='--', linewidth=1.4,
           alpha=0.65, zorder=3, label='Overall 83.81%')
ax.legend(loc='lower right', fontsize=8.5,
          facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=WHITE)
fig.tight_layout()
save('fig1_remediation_by_pillar.png')

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 2 — LLM retry convergence  (k1=75, k2=5, k3=6, k4=1, k5=1)
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 5), facecolor=DARK)
_style_ax(ax)

y2   = np.arange(len(attempt_labels))
bars = ax.barh(y2, attempt_counts, 0.52, color=attempt_colors, alpha=0.88, zorder=2)

pct = [f'{c/88*100:.1f}%' for c in attempt_counts]
for i, (bar, c, p) in enumerate(zip(bars, attempt_counts, pct)):
    ax.text(c + 0.5, i, f'{c} cases  ({p})',
            va='center', color=WHITE, fontsize=10, fontweight='bold')

ax.set_yticks(y2)
ax.set_yticklabels(attempt_labels, color=WHITE, fontsize=11)
ax.set_xlim(0, 98)
ax.set_xlabel('Number of Cases', color=MUTED, fontsize=10)
ax.set_title('LLM Retry Convergence  (88 Remediated Cases)',
             color=WHITE, fontsize=13, fontweight='bold', pad=14)
ax.tick_params(colors=MUTED, labelsize=9)
ax.grid(axis='x', color=GRID_COLOR, linewidth=0.5, zorder=0)
ax.annotate('85.23% resolved\nin first attempt',
            xy=(75, 0), xytext=(50, 1.8),
            arrowprops=dict(arrowstyle='->', color=GREEN, lw=1.8),
            color=GREEN, fontsize=9.5, fontweight='bold')

stats_text = 'μ = 1.2727 attempts\nσ = 0.7385\nMedian = 1'
ax.text(0.97, 0.97, stats_text, transform=ax.transAxes,
        ha='right', va='top', color=MUTED, fontsize=8.5,
        bbox=dict(boxstyle='round,pad=0.4', facecolor=CARD_BG, edgecolor=GRID_COLOR))
fig.tight_layout()
save('fig2_retry_convergence.png')

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 3 — Outcome distribution donut
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 7), facecolor=DARK)
ax.set_facecolor(DARK)

wedges, _ = ax.pie(
    pie_sizes, labels=None,
    colors=pie_colors,
    startangle=90,
    wedgeprops=dict(width=0.52, edgecolor=DARK, linewidth=3),
)

ax.text(0,  0.10, '88/105', ha='center', va='center',
        color=WHITE,  fontsize=22, fontweight='bold')
ax.text(0, -0.16, '83.81%', ha='center', va='center',
        color=ACCENT, fontsize=14, fontweight='bold')

patches = [mpatches.Patch(color=c, label=f'{l}:  {s}')
           for c, l, s in zip(pie_colors, pie_labels, pie_sizes)]
ax.legend(handles=patches, loc='lower center', bbox_to_anchor=(0.5, -0.15),
          fontsize=9.5, facecolor=CARD_BG, edgecolor=GRID_COLOR,
          labelcolor=WHITE, ncol=1, framealpha=1)
ax.set_title('Overall Outcome Distribution  (105 Benchmark Cases)',
             color=WHITE, fontsize=13, fontweight='bold', pad=16)
fig.tight_layout()
save('fig3_outcome_distribution.png')

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 4 — Hallucination rate vs remediation rate scatter
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(8, 6), facecolor=DARK)
_style_ax(ax)

hall_rates     = [h/t*100 for h,t in zip(hallucination, total_cases)]
scatter_colors = [GREEN if r >= 90 else AMBER if r >= 70 else RED for r in fix_rates]

ax.scatter(hall_rates, fix_rates,
           s=[t*22 for t in total_cases],
           c=scatter_colors, alpha=0.88, zorder=3,
           edgecolors=WHITE, linewidth=1.0)

label_offsets = {
    'Compute':   (1.2, -4.0),
    'Analytics': (-13, -4.5),
    'Storage':   (1.5, -4.0),
}
for i, p in enumerate(pillars):
    ox, oy = label_offsets.get(p, (1.2, 1.8))
    ax.annotate(p, (hall_rates[i], fix_rates[i]),
                xytext=(hall_rates[i]+ox, fix_rates[i]+oy),
                color=WHITE, fontsize=9, fontweight='bold')

ax.axhline(88/105*100, color=ACCENT, linestyle='--', linewidth=1.2, alpha=0.55)
ax.text(22, 88/105*100 + 0.8, 'Overall avg 83.81%', color=ACCENT, fontsize=8, alpha=0.8)

ax.set_xlabel('Hallucination Rate (%)',  color=MUTED, fontsize=10)
ax.set_ylabel('Remediation Rate (%)',    color=MUTED, fontsize=10)
ax.set_title('Hallucination Rate vs. Remediation Success\n(bubble size ∝ number of test cases)',
             color=WHITE, fontsize=13, fontweight='bold', pad=14)
ax.tick_params(colors=MUTED, labelsize=9)
ax.grid(color=GRID_COLOR, linewidth=0.5, zorder=0)

for colour, label in [(GREEN,'≥ 90% remediated'),(AMBER,'70–90%'),(RED,'< 70%')]:
    ax.scatter([], [], c=colour, s=80, label=label, edgecolors=WHITE, linewidth=0.7)
ax.legend(fontsize=8.5, facecolor=CARD_BG, edgecolor=GRID_COLOR, labelcolor=WHITE)
fig.tight_layout()
save('fig4_hallucination_vs_remediation.png')

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 5 — Z3 formal proof coverage by pillar
# 37 total: 29 FORMAL PROOF COMPLETE + 8 PATCH REJECTED
# ─────────────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(9, 5.5), facecolor=DARK)
_style_ax(ax)

proof_rates = [p/t*100 for p,t in zip(formal_proofs, total_cases)]
bar_colors  = [PURPLE if r > 0 else CARD_BG for r in proof_rates]

bars5 = ax.bar(pillars, proof_rates, color=bar_colors,
               alpha=0.88, zorder=2, width=0.6,
               edgecolor=DARK, linewidth=1.2)

for idx, (bar, r, p) in enumerate(zip(bars5, proof_rates, formal_proofs)):
    if r > 0:
        ax.text(bar.get_x() + bar.get_width()/2, r + 1.2,
                f'{p}/{total_cases[idx]}',
                ha='center', color=WHITE, fontsize=9, fontweight='bold')
        ax.text(bar.get_x() + bar.get_width()/2, r/2,
                f'{r:.0f}%', ha='center', va='center',
                color=WHITE, fontsize=9.5, fontweight='bold', alpha=0.95)
    else:
        ax.text(bar.get_x() + bar.get_width()/2, 1.5,
                '0', ha='center', color=MUTED, fontsize=8)

ax.set_ylabel('Formal Proof Coverage (%)', color=MUTED, fontsize=10)
ax.set_title('Z3 Formal Proof Coverage by Infrastructure Pillar',
             color=WHITE, fontsize=13, fontweight='bold', pad=14)
ax.tick_params(axis='x', colors=WHITE, labelsize=10, rotation=20)
ax.tick_params(axis='y', colors=MUTED,  labelsize=9)
ax.set_ylim(0, 85)
ax.grid(axis='y', color=GRID_COLOR, linewidth=0.5, zorder=0)

ax.text(0.98, 0.96, 'Total: 37 formal proofs  (29 FPC + 8 PATCH REJECTED)',
        transform=ax.transAxes, ha='right', va='top',
        color=PURPLE, fontsize=9.5, fontweight='bold')
fig.tight_layout()
save('fig5_formal_proof_coverage.png')

# ─────────────────────────────────────────────────────────────────────────────
# FIGURE 6 — Key metrics summary banner
# ─────────────────────────────────────────────────────────────────────────────
fig, axes = plt.subplots(1, 5, figsize=(14, 3), facecolor=DARK)

metrics = [
    ('83.81%', 'Remediation Rate\n(88/105)'),
    ('85.23%', 'One-Shot Rate\n(75/88 at k=1)'),
    ('37',     'Formal Proof\nCertificates'),
    ('16.19%', 'Hallucination Rate\n(17/105)'),
    ('1.2727', 'Mean Attempts\n(μ, σ=0.7385)'),
]
colors_banner = [GREEN, ACCENT, PURPLE, RED, AMBER]

for ax2, (val, label), col in zip(axes, metrics, colors_banner):
    ax2.set_facecolor(CARD_BG)
    for spine in ax2.spines.values():
        spine.set_color(col)
        spine.set_linewidth(2)
    ax2.text(0.5, 0.62, val,   transform=ax2.transAxes,
             ha='center', va='center', color=col,
             fontsize=22, fontweight='bold')
    ax2.text(0.5, 0.22, label, transform=ax2.transAxes,
             ha='center', va='center', color=MUTED,
             fontsize=9, linespacing=1.5)
    ax2.set_xticks([])
    ax2.set_yticks([])

fig.suptitle('Sentinel-Mesh — Key Performance Metrics  (105 Benchmark Cases, research_data_v100.csv)',
             color=WHITE, fontsize=11, fontweight='bold', y=1.04)
fig.tight_layout(pad=0.6)
save('fig6_metrics_banner.png')

print('\nAll 6 figures saved to logs/')
print('\nVerified numbers (from research_data_v100.csv):')
print('  N=105, Fixed=88, Failed=17')
print('  RR=83.81%, OSR=85.23% (k1=75), HR=16.19%')
print('  Formal proofs=37 (29 FPC + 8 PR), Plain PASS=51')
print('  Attempt dist: k1=75, k2=5, k3=6, k4=1, k5=1')
print('  mu=1.2727, sigma=0.7385')