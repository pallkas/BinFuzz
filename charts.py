#!/usr/bin/env python3
"""
BinFuzz — Chart Generation
Produces PNG charts from fuzzing results and BinDiff analysis.
Called automatically at the end of each workflow.
"""

import os
import warnings
warnings.filterwarnings('ignore')          # suppress matplotlib backend noise

import matplotlib
matplotlib.use('Agg')                      # non-interactive backend (no display needed)
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.gridspec as gridspec
import numpy as np

# ── Palette (matches the terminal UI colours) ─────────────────────────────────
C_CYAN    = '#00BCD4'
C_GREEN   = '#4CAF50'
C_YELLOW  = '#FFC107'
C_RED     = '#F44336'
C_BRIGHT  = '#FF5252'
C_BLUE    = '#2196F3'
C_PURPLE  = '#9C27B0'
C_GREY    = '#607D8B'
C_BG      = '#1A1A2E'   # dark background
C_PANEL   = '#16213E'
C_TEXT    = '#E0E0E0'
C_GRID    = '#2A2A4A'

RISK_COLORS = {
    'low':      C_GREEN,
    'medium':   C_YELLOW,
    'high':     C_RED,
    'critical': C_BRIGHT,
}

def _fig_style():
    """Apply global dark-theme style."""
    plt.rcParams.update({
        'figure.facecolor':  C_BG,
        'axes.facecolor':    C_PANEL,
        'axes.edgecolor':    C_GREY,
        'axes.labelcolor':   C_TEXT,
        'axes.titlecolor':   C_TEXT,
        'axes.titlesize':    11,
        'axes.labelsize':    9,
        'xtick.color':       C_TEXT,
        'ytick.color':       C_TEXT,
        'xtick.labelsize':   8,
        'ytick.labelsize':   8,
        'grid.color':        C_GRID,
        'grid.linewidth':    0.5,
        'legend.facecolor':  C_PANEL,
        'legend.edgecolor':  C_GREY,
        'legend.labelcolor': C_TEXT,
        'legend.fontsize':   8,
        'text.color':        C_TEXT,
        'font.family':       'DejaVu Sans',
    })


# ═══════════════════════════════════════════════════════════════════════════════
#  FUZZING CHARTS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_fuzz_charts(fuzz_records: list, output_dir: str,
                         title_prefix: str = '') -> str:
    """
    Generate a fuzzing summary chart and save it as a PNG.

    fuzz_records — list of dicts:
        {
          'binary':   str,        # display name
          'version':  str,        # 'baseline' | 'updated' | 'v1.0' etc.
          'execs':    int,
          'crashes':  int,
          'hangs':    int,
          'coverage': float,      # percent 0-100
        }

    Returns the path to the saved PNG.
    """
    if not fuzz_records:
        return ''

    os.makedirs(output_dir, exist_ok=True)
    _fig_style()

    labels   = [f"{r['binary']}\n({r.get('version','?')})" for r in fuzz_records]
    execs    = [r.get('execs', 0)    for r in fuzz_records]
    crashes  = [r.get('crashes', 0)  for r in fuzz_records]
    hangs    = [r.get('hangs', 0)    for r in fuzz_records]
    coverage = [r.get('coverage', 0) for r in fuzz_records]

    n     = len(fuzz_records)
    x     = np.arange(n)
    width = 0.35

    fig = plt.figure(figsize=(max(10, n * 2.5), 11))
    fig.suptitle(
        f"{title_prefix}Fuzzing Results".strip(),
        fontsize=15, fontweight='bold', color=C_TEXT, y=0.98
    )
    gs = gridspec.GridSpec(2, 2, figure=fig, hspace=0.45, wspace=0.35)

    # ── 1. Coverage bar ───────────────────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    bars = ax1.bar(x, coverage, color=[
        C_GREEN if c < 30 else C_YELLOW if c < 60 else C_RED
        for c in coverage
    ], edgecolor=C_GREY, linewidth=0.6)
    ax1.set_xticks(x); ax1.set_xticklabels(labels, fontsize=7)
    ax1.set_ylabel('Coverage (%)')
    ax1.set_title('Bitmap Coverage')
    ax1.set_ylim(0, max(max(coverage) * 1.25, 5))
    ax1.yaxis.grid(True); ax1.set_axisbelow(True)
    for bar, val in zip(bars, coverage):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.3,
                 f'{val:.1f}%', ha='center', va='bottom', fontsize=7, color=C_TEXT)

    # ── 2. Crashes & Hangs grouped bar ───────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    b1 = ax2.bar(x - width / 2, crashes, width, label='Crashes',
                 color=C_RED, edgecolor=C_GREY, linewidth=0.6)
    b2 = ax2.bar(x + width / 2, hangs,   width, label='Hangs',
                 color=C_YELLOW, edgecolor=C_GREY, linewidth=0.6)
    ax2.set_xticks(x); ax2.set_xticklabels(labels, fontsize=7)
    ax2.set_ylabel('Count')
    ax2.set_title('Crashes vs Hangs')
    ax2.legend()
    ax2.yaxis.grid(True); ax2.set_axisbelow(True)
    for bar, val in zip(list(b1) + list(b2), crashes + hangs):
        if val > 0:
            ax2.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.05,
                     str(val), ha='center', va='bottom', fontsize=8, color=C_TEXT)

    # ── 3. Total executions ───────────────────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, 0])
    bar_colors = [C_CYAN if i % 2 == 0 else C_BLUE for i in range(n)]
    bars3 = ax3.bar(x, execs, color=bar_colors, edgecolor=C_GREY, linewidth=0.6)
    ax3.set_xticks(x); ax3.set_xticklabels(labels, fontsize=7)
    ax3.set_ylabel('Executions')
    ax3.set_title('Total Executions')
    ax3.yaxis.grid(True); ax3.set_axisbelow(True)
    for bar, val in zip(bars3, execs):
        ax3.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(execs) * 0.01,
                 f'{val:,}', ha='center', va='bottom', fontsize=7, color=C_TEXT)

    # ── 4. Crash rate (crashes / 1k execs) ───────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 1])
    crash_rate = [
        (c / e * 1000) if e > 0 else 0
        for c, e in zip(crashes, execs)
    ]
    bars4 = ax4.bar(x, crash_rate, color=[
        C_BRIGHT if r > 0 else C_GREY for r in crash_rate
    ], edgecolor=C_GREY, linewidth=0.6)
    ax4.set_xticks(x); ax4.set_xticklabels(labels, fontsize=7)
    ax4.set_ylabel('Crashes per 1k execs')
    ax4.set_title('Crash Rate')
    ax4.yaxis.grid(True); ax4.set_axisbelow(True)
    for bar, val in zip(bars4, crash_rate):
        if val > 0:
            ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max(crash_rate) * 0.02,
                     f'{val:.2f}', ha='center', va='bottom', fontsize=7, color=C_TEXT)

    out_path = os.path.join(output_dir, 'fuzz_results.png')
    fig.savefig(out_path, dpi=150, bbox_inches='tight', facecolor=C_BG)
    plt.close(fig)
    return out_path


# ═══════════════════════════════════════════════════════════════════════════════
#  BINDIFF CHARTS
# ═══════════════════════════════════════════════════════════════════════════════

def generate_bindiff_charts(changes: list, binary_name: str,
                             output_dir: str) -> str:
    """
    Generate a BinDiff analysis chart and save as PNG.

    changes — list of StructuralChange dataclass instances.
    Returns the path to the saved PNG.
    """
    if not changes:
        return ''

    os.makedirs(output_dir, exist_ok=True)
    _fig_style()

    modified = [c for c in changes if c.change_type == 'modified']
    added    = [c for c in changes if c.change_type == 'added']
    removed  = [c for c in changes if c.change_type == 'removed']
    mem_risk = [c for c in changes if c.is_memory_related]
    par_risk = [c for c in changes if c.is_parsing_related]
    other    = [c for c in changes if not c.is_memory_related and not c.is_parsing_related]

    fig = plt.figure(figsize=(14, 10))
    fig.suptitle(f'BinDiff Analysis — {binary_name}',
                 fontsize=15, fontweight='bold', color=C_TEXT, y=0.98)
    gs = gridspec.GridSpec(2, 3, figure=fig, hspace=0.5, wspace=0.38)

    # ── 1. Change type breakdown (pie) ────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, 0])
    counts = [len(modified), len(added), len(removed)]
    labels = ['Modified', 'Added', 'Removed']
    colors = [C_YELLOW, C_GREEN, C_RED]
    non_zero = [(c, l, col) for c, l, col in zip(counts, labels, colors) if c > 0]
    if non_zero:
        vals, labs, cols = zip(*non_zero)
        wedges, texts, autotexts = ax1.pie(
            vals, labels=labs, colors=cols, autopct='%1.0f%%',
            startangle=90, pctdistance=0.75,
            wedgeprops=dict(linewidth=0.8, edgecolor=C_BG),
        )
        for t in texts + autotexts:
            t.set_color(C_TEXT); t.set_fontsize(8)
    ax1.set_title(f'Change Types\n(total: {len(changes)})')

    # ── 2. Risk category breakdown (pie) ─────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 1])
    risk_counts = [len(mem_risk), len(par_risk), len(other)]
    risk_labels = ['Memory-related', 'Parsing-related', 'Other']
    risk_colors = [C_RED, C_YELLOW, C_GREY]
    non_zero2 = [(c, l, col) for c, l, col in
                 zip(risk_counts, risk_labels, risk_colors) if c > 0]
    if non_zero2:
        vals2, labs2, cols2 = zip(*non_zero2)
        wedges2, texts2, autotexts2 = ax2.pie(
            vals2, labels=labs2, colors=cols2, autopct='%1.0f%%',
            startangle=90, pctdistance=0.75,
            wedgeprops=dict(linewidth=0.8, edgecolor=C_BG),
        )
        for t in texts2 + autotexts2:
            t.set_color(C_TEXT); t.set_fontsize(8)
    ax2.set_title('Risk Categories')

    # ── 3. Similarity score histogram (modified functions only) ───────────────
    ax3 = fig.add_subplot(gs[0, 2])
    if modified:
        scores = [c.similarity_score for c in modified]
        bins   = np.linspace(0, 1, 21)
        n_hist, _, patches = ax3.hist(scores, bins=bins, edgecolor=C_BG, linewidth=0.4)
        for patch, left in zip(patches, bins[:-1]):
            patch.set_facecolor(
                C_BRIGHT if left < 0.5 else C_YELLOW if left < 0.8 else C_GREEN)
        ax3.set_xlabel('Similarity Score')
        ax3.set_ylabel('# Functions')
        ax3.set_title(f'Similarity Distribution\n({len(modified)} modified)')
        ax3.set_xlim(0, 1)
        ax3.yaxis.grid(True); ax3.set_axisbelow(True)
        avg = np.mean(scores)
        ax3.axvline(avg, color=C_CYAN, linestyle='--', linewidth=1.2,
                    label=f'avg={avg:.2f}')
        ax3.legend()
    else:
        ax3.text(0.5, 0.5, 'No modified functions', ha='center', va='center',
                 transform=ax3.transAxes, color=C_GREY)
        ax3.set_title('Similarity Distribution')

    # ── 4. Top 15 most-changed functions (horizontal bar) ─────────────────────
    ax4 = fig.add_subplot(gs[1, :2])
    top = sorted(modified, key=lambda c: c.similarity_score)[:15]
    if top:
        names = [c.function_name[-45:] if len(c.function_name) > 45
                 else c.function_name for c in top]
        sims  = [c.similarity_score for c in top]
        bar_colors = [
            C_BRIGHT if s < 0.5 else C_YELLOW if s < 0.8 else C_GREEN
            for s in sims
        ]
        y_pos = np.arange(len(top))
        bars = ax4.barh(y_pos, sims, color=bar_colors, edgecolor=C_GREY, linewidth=0.5)
        ax4.set_yticks(y_pos)
        ax4.set_yticklabels(names, fontsize=7)
        ax4.set_xlabel('Similarity Score (lower = more changed)')
        ax4.set_title('Top 15 Most-Changed Functions')
        ax4.set_xlim(0, 1.05)
        ax4.axvline(0.8, color=C_GREY, linestyle=':', linewidth=0.8, alpha=0.6)
        ax4.xaxis.grid(True); ax4.set_axisbelow(True)
        for bar, sim, change in zip(bars, sims, top):
            marker = ''
            if change.is_memory_related:  marker += ' [MEM]'
            if change.is_parsing_related: marker += ' [PARSE]'
            if marker:
                ax4.text(sim + 0.01, bar.get_y() + bar.get_height() / 2,
                         marker, va='center', fontsize=6,
                         color=C_RED if change.is_memory_related else C_YELLOW)
    else:
        ax4.text(0.5, 0.5, 'No modified functions detected',
                 ha='center', va='center', transform=ax4.transAxes, color=C_GREY)
        ax4.set_title('Top 15 Most-Changed Functions')

    # ── 5. CFG complexity delta (modified functions) ──────────────────────────
    ax5 = fig.add_subplot(gs[1, 2])
    if modified:
        deltas = [c.cfg_complexity_delta for c in modified]
        pos_d  = sum(1 for d in deltas if d > 0)
        neg_d  = sum(1 for d in deltas if d < 0)
        zero_d = sum(1 for d in deltas if d == 0)
        ax5.bar(['Increased\ncomplexity', 'Decreased\ncomplexity', 'Unchanged'],
                [pos_d, neg_d, zero_d],
                color=[C_RED, C_GREEN, C_GREY],
                edgecolor=C_BG, linewidth=0.6)
        ax5.set_ylabel('# Functions')
        ax5.set_title('CFG Complexity\nDelta (modified)')
        ax5.yaxis.grid(True); ax5.set_axisbelow(True)
        for i, val in enumerate([pos_d, neg_d, zero_d]):
            ax5.text(i, val + 0.1, str(val), ha='center', va='bottom',
                     fontsize=9, color=C_TEXT)
    else:
        ax5.text(0.5, 0.5, 'No data', ha='center', va='center',
                 transform=ax5.transAxes, color=C_GREY)
        ax5.set_title('CFG Complexity Delta')

    out_path = os.path.join(output_dir, 'bindiff_results.png')
    fig.savefig(out_path, dpi=150, bbox_inches='tight', facecolor=C_BG)
    plt.close(fig)
    return out_path


# ═══════════════════════════════════════════════════════════════════════════════
#  MARL FULL-FORECAST COMBINED DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════

def generate_marl_dashboard(forecast_records: list, output_dir: str) -> str:
    """
    Generate a combined dashboard after a full MARL batch run.

    forecast_records — list of dicts produced by marl_workflow():
        {
          'binary':           str,
          'risk':             str,    # 'low' | 'medium' | 'high' | 'critical'
          'score':            float,  # combined risk 0-100
          'structural_score': float,
          'behavioral_score': float,
          'dependency_score': float,
          'baseline_crashes': int,
          'updated_crashes':  int,
          'baseline_cov':     float,
          'updated_cov':      float,
          'changed_funcs':    int,
          'memory_funcs':     int,
          'parsing_funcs':    int,
        }

    Returns path to saved PNG.
    """
    if not forecast_records:
        return ''

    os.makedirs(output_dir, exist_ok=True)
    _fig_style()

    names   = [r['binary'] for r in forecast_records]
    scores  = [r.get('score', 0)            for r in forecast_records]
    s_risk  = [r.get('structural_score', 0) for r in forecast_records]
    b_risk  = [r.get('behavioral_score', 0) for r in forecast_records]
    d_risk  = [r.get('dependency_score', 0) for r in forecast_records]
    bl_cr   = [r.get('baseline_crashes', 0) for r in forecast_records]
    up_cr   = [r.get('updated_crashes', 0)  for r in forecast_records]
    bl_cov  = [r.get('baseline_cov', 0)     for r in forecast_records]
    up_cov  = [r.get('updated_cov', 0)      for r in forecast_records]
    chg     = [r.get('changed_funcs', 0)    for r in forecast_records]
    mem_f   = [r.get('memory_funcs', 0)     for r in forecast_records]
    par_f   = [r.get('parsing_funcs', 0)    for r in forecast_records]

    n     = len(forecast_records)
    x     = np.arange(n)
    width = 0.35

    fig = plt.figure(figsize=(16, 12))
    fig.suptitle('BinFuzz — MARL Vulnerability Forecast Dashboard',
                 fontsize=16, fontweight='bold', color=C_TEXT, y=0.99)
    gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.5, wspace=0.38)

    # ── 1. Combined risk score ────────────────────────────────────────────────
    ax1 = fig.add_subplot(gs[0, :2])
    risk_colors = [RISK_COLORS.get(r.get('risk', 'low'), C_GREY)
                   for r in forecast_records]
    bars1 = ax1.bar(x, scores, color=risk_colors, edgecolor=C_BG, linewidth=0.6)
    ax1.axhline(30, color=C_GREEN,  linestyle=':', linewidth=0.8, alpha=0.7, label='Low/Medium')
    ax1.axhline(60, color=C_YELLOW, linestyle=':', linewidth=0.8, alpha=0.7, label='Medium/High')
    ax1.axhline(85, color=C_RED,    linestyle=':', linewidth=0.8, alpha=0.7, label='High/Critical')
    ax1.set_xticks(x); ax1.set_xticklabels(names, fontsize=9)
    ax1.set_ylabel('Risk Score (0–100)')
    ax1.set_title('Combined Vulnerability Risk Score')
    ax1.set_ylim(0, 105)
    ax1.legend(fontsize=7, loc='upper right')
    ax1.yaxis.grid(True); ax1.set_axisbelow(True)
    for bar, val, r in zip(bars1, scores, forecast_records):
        ax1.text(bar.get_x() + bar.get_width() / 2, val + 1.5,
                 f"{val:.1f}\n{r.get('risk','?').upper()}",
                 ha='center', va='bottom', fontsize=7, color=C_TEXT, fontweight='bold')

    # ── 2. Risk category summary (pie) ───────────────────────────────────────
    ax2 = fig.add_subplot(gs[0, 2])
    risk_counts = {}
    for r in forecast_records:
        risk_counts[r.get('risk', 'low')] = risk_counts.get(r.get('risk', 'low'), 0) + 1
    if risk_counts:
        pcolors = [RISK_COLORS.get(k, C_GREY) for k in risk_counts]
        wedges, texts, autotexts = ax2.pie(
            risk_counts.values(),
            labels=[k.capitalize() for k in risk_counts],
            colors=pcolors, autopct='%1.0f%%', startangle=90,
            pctdistance=0.75, wedgeprops=dict(linewidth=0.8, edgecolor=C_BG),
        )
        for t in texts + autotexts:
            t.set_color(C_TEXT); t.set_fontsize(8)
    ax2.set_title('Risk Distribution')

    # ── 3. Stacked risk score components ─────────────────────────────────────
    ax3 = fig.add_subplot(gs[1, :2])
    ax3.bar(x, s_risk, label='Structural', color=C_RED,    edgecolor=C_BG, linewidth=0.4)
    ax3.bar(x, b_risk, bottom=s_risk, label='Behavioral',
            color=C_YELLOW, edgecolor=C_BG, linewidth=0.4)
    ax3.bar(x, d_risk, bottom=[s + b for s, b in zip(s_risk, b_risk)],
            label='Dependency', color=C_BLUE, edgecolor=C_BG, linewidth=0.4)
    ax3.set_xticks(x); ax3.set_xticklabels(names, fontsize=9)
    ax3.set_ylabel('Score')
    ax3.set_title('Risk Score Components (Structural / Behavioral / Dependency)')
    ax3.legend(fontsize=8, loc='upper right')
    ax3.yaxis.grid(True); ax3.set_axisbelow(True)

    # ── 4. Crashes: baseline vs updated ──────────────────────────────────────
    ax4 = fig.add_subplot(gs[1, 2])
    ax4.bar(x - width / 2, bl_cr, width, label='Baseline',
            color=C_CYAN, edgecolor=C_BG, linewidth=0.4)
    ax4.bar(x + width / 2, up_cr, width, label='Updated',
            color=C_BRIGHT, edgecolor=C_BG, linewidth=0.4)
    ax4.set_xticks(x); ax4.set_xticklabels(names, fontsize=8)
    ax4.set_ylabel('Unique Crashes')
    ax4.set_title('Crashes\n(Baseline vs Updated)')
    ax4.legend(fontsize=8)
    ax4.yaxis.grid(True); ax4.set_axisbelow(True)

    # ── 5. Coverage: baseline vs updated ─────────────────────────────────────
    ax5 = fig.add_subplot(gs[2, 0])
    ax5.bar(x - width / 2, bl_cov, width, label='Baseline',
            color=C_CYAN, edgecolor=C_BG, linewidth=0.4)
    ax5.bar(x + width / 2, up_cov, width, label='Updated',
            color=C_GREEN, edgecolor=C_BG, linewidth=0.4)
    ax5.set_xticks(x); ax5.set_xticklabels(names, fontsize=8)
    ax5.set_ylabel('Coverage (%)')
    ax5.set_title('Coverage (Baseline vs Updated)')
    ax5.legend(fontsize=8)
    ax5.yaxis.grid(True); ax5.set_axisbelow(True)

    # ── 6. Structural changes count ───────────────────────────────────────────
    ax6 = fig.add_subplot(gs[2, 1])
    ax6.bar(x, chg, label='Total Changes',
            color=C_PURPLE, edgecolor=C_BG, linewidth=0.4)
    ax6.bar(x, mem_f, label='Memory-related',
            color=C_RED, edgecolor=C_BG, linewidth=0.4)
    ax6.bar(x, par_f, label='Parsing-related',
            color=C_YELLOW, edgecolor=C_BG, linewidth=0.4, alpha=0.8)
    ax6.set_xticks(x); ax6.set_xticklabels(names, fontsize=8)
    ax6.set_ylabel('# Functions')
    ax6.set_title('Structural Changes')
    ax6.legend(fontsize=7)
    ax6.yaxis.grid(True); ax6.set_axisbelow(True)

    # ── 7. Memory vs parsing risk heatmap ─────────────────────────────────────
    ax7 = fig.add_subplot(gs[2, 2])
    if n > 0:
        heat = np.array([[m, p] for m, p in zip(mem_f, par_f)], dtype=float)
        if heat.max() > 0:
            heat = heat / heat.max()
        im = ax7.imshow(heat.T, aspect='auto', cmap='RdYlGn_r',
                        vmin=0, vmax=1, interpolation='nearest')
        ax7.set_xticks(range(n)); ax7.set_xticklabels(names, fontsize=8, rotation=30)
        ax7.set_yticks([0, 1])
        ax7.set_yticklabels(['Memory\nRisk', 'Parsing\nRisk'], fontsize=8)
        plt.colorbar(im, ax=ax7, label='Relative Risk (normalised)', shrink=0.8)
        for i in range(n):
            for j, val in enumerate([mem_f[i], par_f[i]]):
                ax7.text(i, j, str(val), ha='center', va='center',
                         fontsize=9, color='white', fontweight='bold')
    ax7.set_title('Risk Heatmap')

    out_path = os.path.join(output_dir, 'marl_dashboard.png')
    fig.savefig(out_path, dpi=150, bbox_inches='tight', facecolor=C_BG)
    plt.close(fig)
    return out_path
