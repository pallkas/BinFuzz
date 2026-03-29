#!/usr/bin/env python3
"""
BinFuzz - Production Runner
Uses real binaries from configured directory structure
"""

import sys
import os
import re
import json
import time
import shutil
import argparse
import subprocess
import logging
import urllib.request
import urllib.parse
import urllib.error
from pathlib import Path

# ── ANSI colors ───────────────────────────────────────────────────────────────
RESET      = "\033[0m"
BOLD       = "\033[1m"
DIM        = "\033[2m"
RED        = "\033[31m"
GREEN      = "\033[32m"
YELLOW     = "\033[33m"
BLUE       = "\033[34m"
CYAN       = "\033[36m"
BRIGHT_RED = "\033[91m"

W = 80

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from marl_vuln_forecast import (MARLVulnerabilityForecaster,
                                 BinDiffAnalyzerAgent,
                                 FuzzingCoordinatorAgent)
from charts import (generate_fuzz_charts,
                    generate_bindiff_charts,
                    generate_marl_dashboard)

# ── Logging: file + console ───────────────────────────────────────────────────
_fmt    = logging.Formatter('%(asctime)s  %(name)-28s  %(message)s', datefmt='%H:%M:%S')
_file_h = logging.FileHandler('production.log')
_file_h.setFormatter(_fmt)
_con_h  = logging.StreamHandler(sys.stdout)
_con_h.setFormatter(_fmt)
logging.basicConfig(level=logging.INFO, handlers=[_file_h, _con_h])
logger = logging.getLogger(__name__)


# ── UI primitives ─────────────────────────────────────────────────────────────

def _visible_len(s: str) -> int:
    return len(re.sub(r'\033\[[0-9;]*m', '', s))

def _pad(content: str, width: int) -> str:
    return content + ' ' * max(0, width - _visible_len(content))

def risk_color(level: str) -> str:
    return {'low': GREEN, 'medium': YELLOW,
            'high': RED, 'critical': BRIGHT_RED}.get(level.lower(), '')

def score_bar(score: float, width: int = 32) -> str:
    filled = int(score / 100 * width)
    bar    = '█' * filled + '░' * (width - filled)
    color  = GREEN if score < 30 else YELLOW if score < 60 else RED if score < 85 else BRIGHT_RED
    return f"{color}{bar}{RESET}"

def box(title: str, lines: list, width: int = W) -> None:
    inner     = width - 4
    title_str = f" {BOLD}{title}{RESET} "
    top_fill  = '─' * max(0, width - 2 - _visible_len(title_str))
    print(f"┌{title_str}{top_fill}┐")
    for line in lines:
        print(f"│  {_pad(line, inner)}  │")
    print(f"└{'─' * (width - 2)}┘")

def status(msg: str, kind: str = 'run') -> None:
    icons = {'run': f"{CYAN}▶{RESET}", 'ok': f"{GREEN}✔{RESET}",
             'err': f"{RED}✗{RESET}", 'info': f"{BLUE}ℹ{RESET}",
             'warn': f"{YELLOW}⚠{RESET}"}
    print(f"  {icons.get(kind, ' ')} {msg}")

def print_table(headers: list, rows: list, widths: list) -> None:
    sep_top = '┬'.join('─' * (w + 2) for w in widths)
    sep_mid = '┼'.join('─' * (w + 2) for w in widths)
    sep_bot = '┴'.join('─' * (w + 2) for w in widths)

    def row_str(cells):
        parts = []
        for cell, w in zip(cells, widths):
            if isinstance(cell, tuple):
                text, color = cell
                parts.append(f" {color}{text:<{w}}{RESET} ")
            else:
                parts.append(f" {cell:<{w}} ")
        return '│'.join(parts)

    print(f"┌{sep_top}┐")
    print(f"│{row_str([f'{BOLD}{h}{RESET}' for h in headers])}│")
    print(f"├{sep_mid}┤")
    for row in rows:
        print(f"│{row_str(row)}│")
    print(f"└{sep_bot}┘")

def print_forecast(forecast, binary_name: str = '') -> None:
    level = forecast.risk_category
    rc    = risk_color(level)
    score = forecast.combined_risk_score
    bar   = score_bar(score)
    lines = []
    if binary_name:
        lines += [f"{DIM}Binary      {RESET}  {binary_name}", '']
    lines += [
        f"{DIM}Risk Level  {RESET}  {rc}{BOLD}{level.upper()}{RESET}  {rc}●{RESET}",
        f"{DIM}Score       {RESET}  {rc}{score:5.2f}{RESET} / 100  [{bar}]",
        '',
        f"{DIM}Structural  {RESET}  {forecast.structural_risk_score:5.2f}",
        f"{DIM}Behavioral  {RESET}  {forecast.behavioral_risk_score:5.2f}",
        f"{DIM}Dependency  {RESET}  {forecast.dependency_risk_score:5.2f}",
    ]
    box('FORECAST RESULTS', lines)

def print_recommendations(recs: list) -> None:
    if not recs:
        return
    lines = []
    max_w = W - 8
    for i, rec in enumerate(recs, 1):
        words, line, first = rec.split(), '', True
        for word in words:
            if len(line) + len(word) + 1 > max_w:
                prefix = f"{DIM}{i}.{RESET} " if first else '   '
                lines.append(f"{prefix}{line.strip()}")
                first, line = False, word + ' '
            else:
                line += word + ' '
        if line.strip():
            prefix = f"{DIM}{i}.{RESET} " if first else '   '
            lines.append(f"{prefix}{line.strip()}")
    box('RECOMMENDATIONS', lines)

def section(title: str) -> None:
    print()
    print(f"╔{'═' * (W - 2)}╗")
    label = f"  {BOLD}{title}{RESET}"
    print(f"║{CYAN}{_pad(label, W - 2)}{RESET}║")
    print(f"╚{'═' * (W - 2)}╝\n")

def _menu(title: str, items: list, back_label: str = 'Back') -> None:
    """Render a numbered menu. items = [(label, description), ...]"""
    print(f"\n┌{'─' * (W - 2)}┐")
    print(f"│{_pad(f'  {BOLD}{title}{RESET}', W - 2)}│")
    print(f"├{'─' * 6}┬{'─' * (W - 9)}┤")
    for i, (label, desc) in enumerate(items, 1):
        num  = f"  {CYAN}[{i}]{RESET} "
        body = f"  {label}  {DIM}{desc}{RESET}" if desc else f"  {label}"
        print(f"│{_pad(num, 6)}│{_pad(body, W - 9)}│")
    print(f"├{'─' * 6}┼{'─' * (W - 9)}┤")
    print(f"│{_pad(f'  {DIM}[0]{RESET} ', 6)}│{_pad(f'  {DIM}{back_label}{RESET}', W - 9)}│")
    print(f"└{'─' * 6}┴{'─' * (W - 9)}┘\n")

def _pick(prompt: str, lo: int, hi: int) -> int:
    """Read a validated integer from stdin. Returns -1 on bad input."""
    raw = input(f"  {BOLD}{prompt}{RESET} {DIM}(0–{hi}){RESET}: ").strip()
    try:
        n = int(raw)
        if lo <= n <= hi:
            return n
    except ValueError:
        pass
    status(f"Please enter a number between {lo} and {hi}", 'err')
    return -1

def print_banner() -> None:
    art = [
        r"  ██████╗ ██╗███╗   ██╗███████╗██╗   ██╗███████╗███████╗",
        r"  ██╔══██╗██║████╗  ██║██╔════╝██║   ██║╚══███╔╝╚══███╔╝",
        r"  ██████╔╝██║██╔██╗ ██║█████╗  ██║   ██║  ███╔╝   ███╔╝ ",
        r"  ██╔══██╗██║██║╚██╗██║██╔══╝  ██║   ██║ ███╔╝   ███╔╝  ",
        r"  ██████╔╝██║██║ ╚████║██║     ╚██████╔╝███████╗███████╗ ",
        r"  ╚═════╝ ╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝╚══════╝",
    ]
    subtitle = "Production Runner  ·  Real Binary Vulnerability Forecasting"
    print()
    print(f"┌{'─' * (W - 2)}┐")
    for line in art:
        print(f"│{CYAN}{BOLD}{_pad(line, W - 2)}{RESET}│")
    print(f"│{' ' * (W - 2)}│")
    sub_pad = (W - 2 - len(subtitle)) // 2
    print(f"│{' ' * sub_pad}{DIM}{subtitle}{RESET}{' ' * (W - 2 - sub_pad - len(subtitle))}│")
    print(f"└{'─' * (W - 2)}┘")
    print()


# ── Config / verification helpers ─────────────────────────────────────────────

def load_config(config_path: str = "config.json") -> dict:
    try:
        with open(config_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        status(f"Configuration file not found: {config_path}", 'err')
        sys.exit(1)
    except json.JSONDecodeError as e:
        status(f"Invalid JSON in configuration file: {e}", 'err')
        sys.exit(1)

def verify_binary_exists(path: str) -> bool:
    if not os.path.exists(path):
        logger.error(f"Binary not found: {path}")
        return False
    if not os.path.isfile(path):
        logger.error(f"Path is not a file: {path}")
        return False
    return True

def verify_corpus_exists(path: str) -> bool:
    if not os.path.exists(path) or not os.path.isdir(path):
        logger.error(f"Corpus directory not found: {path}")
        return False
    files = list(Path(path).glob("*"))
    if not files:
        logger.warning(f"Corpus directory is empty: {path}")
        return False
    logger.info(f"Found {len(files)} files in corpus")
    return True

def list_all_binaries(config: dict) -> list:
    """Return a flat list of every individual binary entry from config."""
    entries = []
    for binary_name, versions in config.get('binaries', {}).items():
        for vtype in ('baseline', 'updated'):
            if vtype in versions:
                e = versions[vtype]
                entries.append({
                    'label':   f"{binary_name}  ({vtype}  v{e.get('version', '?')})",
                    'name':    binary_name,
                    'vtype':   vtype,
                    'path':    e['path'],
                    'version': e.get('version', '?'),
                })
    return entries

def discover_seed_dirs() -> list:
    """Find available AFL++ corpus directories under seeds/."""
    script_dir = Path(__file__).parent
    seed_root  = script_dir / 'seeds'
    dirs = []
    if not seed_root.exists():
        return dirs
    # Flat corpus dirs first (AFL++ ready — one file per seed)
    for family in ('llama', 'onnx'):
        flat = seed_root / family / 'corpus'
        if flat.is_dir():
            files = [f for f in flat.iterdir() if f.is_file()]
            if files:
                dirs.append({
                    'label': f"{family}/corpus  —  {len(files)} seeds (AFL++ ready)",
                    'path':  str(flat),
                })
    # Individual category dirs
    for cat_dir in sorted(seed_root.rglob('*')):
        if (cat_dir.is_dir()
                and cat_dir.name != 'corpus'
                and cat_dir.parent.parent == seed_root):
            files = [f for f in cat_dir.iterdir() if f.is_file()]
            if files:
                rel = cat_dir.relative_to(seed_root)
                dirs.append({
                    'label': f"{rel}  —  {len(files)} seeds",
                    'path':  str(cat_dir),
                })
    return dirs


# ── AFL++ live monitoring ─────────────────────────────────────────────────────

def _read_fuzzer_stats(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            result = {}
            for line in f:
                if ':' in line:
                    k, v = line.strip().split(':', 1)
                    result[k.strip()] = v.strip()
        return result
    except Exception:
        return {}

def _poll_afl_live(proc: subprocess.Popen, session_dir: str,
                   timeout: int, poll: int = 10) -> None:
    """Print a live stats line every `poll` seconds while AFL++ runs."""
    stats_file = os.path.join(session_dir, 'default', 'fuzzer_stats')
    elapsed    = 0
    print()
    print(f"  {DIM}Live stats every {poll}s — Ctrl-C to stop early{RESET}")
    print(f"  {'─' * (W - 4)}")
    try:
        while proc.poll() is None:
            time.sleep(poll)
            elapsed += poll
            s = _read_fuzzer_stats(stats_file)
            if s:
                crashes = int(s.get('saved_crashes', 0) or s.get('unique_crashes', 0))
                hangs   = s.get('saved_hangs') or s.get('unique_hangs', '0')
                cc      = BRIGHT_RED if crashes > 0 else GREEN
                print(f"  {DIM}[{elapsed:>5}s]{RESET}"
                      f"  execs={BOLD}{int(s.get('execs_done',0)):>10,}{RESET}"
                      f"  crashes={cc}{BOLD}{crashes}{RESET}"
                      f"  hangs={hangs}"
                      f"  cov={CYAN}{s.get('bitmap_cvg','?')}{RESET}"
                      f"  eps={s.get('execs_per_sec','?')}")
            else:
                print(f"  {DIM}[{elapsed:>5}s]  waiting for AFL++ to initialise ...{RESET}")
    except KeyboardInterrupt:
        print()
        status("Stopping AFL++ early ...", 'warn')
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        return
    # Normal finish
    try:
        proc.wait(timeout=timeout + 60)
    except subprocess.TimeoutExpired:
        proc.terminate()
    print(f"  {'─' * (W - 4)}")

def _show_afl_results(session_dir: str, binary_path: str) -> None:
    """Display final fuzzer_stats after a campaign ends."""
    s = _read_fuzzer_stats(os.path.join(session_dir, 'default', 'fuzzer_stats'))
    if not s:
        status("No stats file found — AFL++ may not have started correctly", 'warn')
        return
    crashes = int(s.get('saved_crashes', 0) or s.get('unique_crashes', 0))
    hangs   = s.get('saved_hangs') or s.get('unique_hangs', '0')
    cc      = BRIGHT_RED if crashes > 0 else GREEN
    lines   = [
        f"{DIM}Binary    {RESET}  {os.path.basename(binary_path)}",
        '',
        f"{DIM}Execs     {RESET}  {int(s.get('execs_done',0)):,}",
        f"{DIM}Crashes   {RESET}  {cc}{BOLD}{crashes}{RESET}",
        f"{DIM}Hangs     {RESET}  {hangs}",
        f"{DIM}Coverage  {RESET}  {CYAN}{s.get('bitmap_cvg','?')}{RESET}",
        f"{DIM}Eps       {RESET}  {s.get('execs_per_sec','?')}",
    ]
    crash_dir = os.path.join(session_dir, 'default', 'crashes')
    if crashes > 0:
        lines += ['', f"{BRIGHT_RED}Crash inputs → {RESET}{DIM}{crash_dir}{RESET}"]
    print()
    box('AFL++ RESULTS', lines)

    if crashes > 0:
        show_crash_triage(crash_dir, binary_path)


# ── Standalone AFL++ (no MARL) ────────────────────────────────────────────────

def run_baseline_afl(binary_path: str, corpus_dir: str,
                     workspace: str, timeout: int) -> None:
    """Run AFL++ in QEMU mode directly — no MARL, no risk scoring."""
    agent = FuzzingCoordinatorAgent()

    binary_args = agent._get_binary_args(binary_path)
    if binary_args is None:
        status(f"{os.path.basename(binary_path)} needs a harness (.so / server) — cannot fuzz directly", 'err')
        return
    if not shutil.which('afl-fuzz'):
        status("afl-fuzz not in PATH", 'err')
        return

    out_dir = os.path.join(workspace, 'standalone_fuzz')
    os.makedirs(out_dir, exist_ok=True)

    run_ts      = int(time.time())
    session_dir = os.path.join(out_dir, str(run_ts))
    log_file    = os.path.join(out_dir, f'afl_{run_ts}.log')

    afl_input    = agent._prepare_afl_corpus(binary_path, corpus_dir, out_dir)
    afl_dict     = agent._find_afl_dictionary(binary_path)
    instrumented = agent._is_instrumented(binary_path)

    cmd  = ['afl-fuzz']
    if not instrumented:
        cmd += ['-Q']
    cmd += ['-i', afl_input, '-o', session_dir, '-m', 'none', '-t', '5000']
    if timeout > 0:
        cmd += ['-V', str(timeout)]
    if afl_dict:
        cmd += ['-x', afl_dict]
    cmd += ['--', binary_path] + binary_args

    env = {**os.environ,
           'AFL_SKIP_CPUFREQ':                      '1',
           'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES': '1'}

    # Sanitizer policy:
    #   QEMU mode  — no preloading (libqasan causes SIGILL; system libasan
    #                conflicts with QEMU's virtual address layout).
    #   Native mode — preload system libasan.
    san_tag = ''
    if instrumented:
        libasan = agent._find_libasan()
        if libasan:
            env['AFL_PRELOAD']  = libasan
            env['ASAN_OPTIONS'] = ('detect_leaks=0:abort_on_error=1:'
                                   'symbolize=0:fast_unwind_on_malloc=0')
            san_tag = '+ASAN'

    mode_tag = ('QEMU' if not instrumented else 'native') + san_tag

    print()
    status(f"Mode        {DIM}{mode_tag}{RESET}", 'info')
    status(f"Binary      {DIM}{binary_path}{RESET}", 'info')
    status(f"Corpus      {DIM}{afl_input}  ({len(list(Path(afl_input).iterdir()))} files){RESET}", 'info')
    status(f"Dictionary  {DIM}{afl_dict or 'none'}{RESET}", 'info')
    status(f"Duration    {DIM}{timeout}s{RESET}", 'info')
    print()
    status(f"CMD: {DIM}{' '.join(cmd)}{RESET}", 'info')
    print()
    status("Launching AFL++ ...", 'run')

    try:
        # Keep lf open for the entire duration — closing it before AFL++ finishes
        # causes AFL++ to receive SIGPIPE on its first write and die immediately.
        with open(log_file, 'w') as lf:
            proc = subprocess.Popen(cmd, stdout=lf, stderr=subprocess.STDOUT, env=env)
            status(f"AFL++ PID {proc.pid}  |  log → {DIM}{log_file}{RESET}", 'ok')
            _poll_afl_live(proc, session_dir, timeout)
    except Exception as e:
        status(f"AFL++ failed to launch: {e}", 'err')
        return

    _show_afl_results(session_dir, binary_path)

    # ── Generate chart ────────────────────────────────────────────────────────
    s = _read_fuzzer_stats(os.path.join(session_dir, 'default', 'fuzzer_stats'))
    if s:
        record = {
            'binary':   os.path.basename(binary_path),
            'version':  'baseline',
            'execs':    int(s.get('execs_done', 0)),
            'crashes':  int(s.get('saved_crashes', 0) or s.get('unique_crashes', 0)),
            'hangs':    int(s.get('saved_hangs', 0)   or s.get('unique_hangs', 0)),
            'coverage': float(str(s.get('bitmap_cvg', '0')).rstrip('%')),
        }
        chart_dir = os.path.join(out_dir, 'charts')
        chart_path = generate_fuzz_charts([record], chart_dir,
                                          title_prefix=f'{os.path.basename(binary_path)} — ')
        if chart_path:
            status(f"Chart saved  {DIM}{chart_path}{RESET}", 'ok')


# ── Crash triage ──────────────────────────────────────────────────────────────

_SIGNAL_NAMES = {
    1: 'SIGHUP', 2: 'SIGINT',  3: 'SIGQUIT', 4:  'SIGILL',
    5: 'SIGTRAP', 6: 'SIGABRT', 7: 'SIGBUS',  8:  'SIGFPE',
    9: 'SIGKILL', 11: 'SIGSEGV', 13: 'SIGPIPE', 15: 'SIGTERM',
}

# ASAN output patterns → crash classification
_CRASH_CLASSES = {
    'heap-buffer-overflow': {
        'severity':       'CRITICAL',
        'vuln_class':     'Heap Buffer Overflow',
        'exploitability': 'Likely exploitable',
        'why': (
            'Writes or reads past the end of a heap allocation. Attackers can '
            'corrupt adjacent heap metadata or data, enabling arbitrary code '
            'execution or sensitive data disclosure.'
        ),
        'next': (
            'Replay under AddressSanitizer for the exact allocation size and '
            'overflow offset. Review every parser and allocation path for '
            'missing bounds checks.'
        ),
    },
    'stack-buffer-overflow': {
        'severity':       'CRITICAL',
        'vuln_class':     'Stack Buffer Overflow',
        'exploitability': 'Likely exploitable',
        'why': (
            'A stack-allocated buffer was overflowed. A saved return address or '
            'function pointer on the stack can be overwritten, enabling '
            'control-flow hijacking and code execution.'
        ),
        'next': (
            'Build with -fstack-protector-strong and ASAN. Identify the '
            'overflowing stack variable and add a hard bounds check.'
        ),
    },
    'use-after-free': {
        'severity':       'CRITICAL',
        'vuln_class':     'Use-After-Free',
        'exploitability': 'Likely exploitable',
        'why': (
            'Memory is accessed after being freed. A subsequent allocation can '
            'fill the freed region with attacker-controlled data, turning the '
            'dangling read/write into code execution or info disclosure.'
        ),
        'next': (
            'Run under ASAN and valgrind to locate the free site. Audit '
            'ownership and lifetime of the object; set freed pointers to NULL.'
        ),
    },
    'double-free': {
        'severity':       'HIGH',
        'vuln_class':     'Double-Free',
        'exploitability': 'Possibly exploitable',
        'why': (
            'Freeing the same pointer twice corrupts the heap allocator '
            'free-list. Depending on the allocator this can be turned into an '
            'arbitrary write or code execution primitive.'
        ),
        'next': (
            'Set freed pointers to NULL immediately after free. Audit all '
            'ownership-transfer paths for duplicate release.'
        ),
    },
    'null-dereference': {
        'severity':       'MEDIUM',
        'vuln_class':     'Null Dereference',
        'exploitability': 'DoS only (usually)',
        'why': (
            'A NULL pointer was dereferenced, crashing the process. On most '
            'modern systems this is a reliable denial-of-service. On kernels '
            'with mmap-null enabled it can occasionally be elevated.'
        ),
        'next': (
            'Add a NULL check before the dereference and trace back the code '
            'path that produced the NULL return value.'
        ),
    },
    'global-buffer-overflow': {
        'severity':       'HIGH',
        'vuln_class':     'Global Buffer Overflow',
        'exploitability': 'Possibly exploitable',
        'why': (
            'A global or static buffer was overflowed. Adjacent global '
            'variables or function pointers can be corrupted, causing '
            'misdirected control flow or silent data corruption.'
        ),
        'next': (
            'Audit the global array and the write operation that overflows it; '
            'add explicit size limits and static assertions.'
        ),
    },
    'stack-overflow': {
        'severity':       'MEDIUM',
        'vuln_class':     'Stack Overflow (unbounded recursion)',
        'exploitability': 'DoS only',
        'why': (
            'The call stack grew unboundedly — typically from unbounded '
            'recursion on crafted input — exhausting stack space and killing '
            'the process.'
        ),
        'next': (
            'Add a recursion depth counter and a hard limit, or refactor the '
            'algorithm to use an explicit stack (iterative).'
        ),
    },
    'container-overflow': {
        'severity':       'HIGH',
        'vuln_class':     'Container Overflow',
        'exploitability': 'Possibly exploitable',
        'why': (
            'Access past the end of an STL container (vector, string, etc.). '
            'Can expose adjacent heap data, corrupt allocator metadata, or '
            'allow attacker-controlled writes to adjacent objects.'
        ),
        'next': (
            'Switch to bounds-checked access (.at()) and add size assertions '
            'before indexed writes.'
        ),
    },
}

# Signal-only fallback classifications (used when ASAN output is unavailable)
_SIGNAL_CLASSES = {
    11: {
        'severity':       'HIGH',
        'vuln_class':     'Segmentation Fault',
        'exploitability': 'Unknown — needs further analysis',
        'why': (
            'An invalid memory access (null deref, out-of-bounds read/write, '
            'or dangling pointer) caused a segfault. Without ASAN the exact '
            'root cause is unknown and could range from a DoS to a full '
            'memory-corruption exploit.'
        ),
        'next': (
            'Replay with ASAN (-fsanitize=address) to pin down the exact '
            'memory error type. Use: gdb -ex run --args <binary> <crash_file>'
        ),
    },
    6: {
        'severity':       'MEDIUM',
        'vuln_class':     'Abort / Assertion Failure',
        'exploitability': 'DoS likely; investigate for heap corruption',
        'why': (
            'The process called abort(), triggered an assertion, or was '
            'terminated by a sanitizer guard. If induced by heap corruption '
            'it may be escalatable to code execution.'
        ),
        'next': (
            'Check stderr for the assertion message. Rebuild with ASAN '
            'and replay to determine whether heap corruption preceded the abort.'
        ),
    },
    4: {
        'severity':       'HIGH',
        'vuln_class':     'Illegal Instruction',
        'exploitability': 'Possibly exploitable (control-flow corruption)',
        'why': (
            'The CPU executed an invalid instruction. This commonly indicates '
            'a corrupted function pointer or a jump into attacker-controlled '
            'data — a strong signal for control-flow hijacking.'
        ),
        'next': (
            'Attach GDB at the crash: gdb -ex run --args <binary> <crash_file> '
            'then inspect $rip to determine how the instruction pointer was '
            'corrupted.'
        ),
    },
    8: {
        'severity':       'LOW',
        'vuln_class':     'Arithmetic Exception',
        'exploitability': 'DoS only (usually)',
        'why': (
            'A divide-by-zero or integer overflow was triggered. While '
            'typically a DoS, integer overflows in size calculations can '
            'produce undersized allocations and lead to downstream heap '
            'overflows.'
        ),
        'next': (
            'Locate the arithmetic expression and add zero / range checks. '
            'Use compiler flags -fsanitize=integer for broader coverage.'
        ),
    },
    7: {
        'severity':       'MEDIUM',
        'vuln_class':     'Bus Error (misaligned access)',
        'exploitability': 'DoS likely',
        'why': (
            'A misaligned memory access caused a bus error. Typically a DoS, '
            'but alignment bugs can co-occur with other memory errors that '
            'are exploitable.'
        ),
        'next': (
            'Run under valgrind --tool=exp-sgcheck. Check struct packing '
            'directives and pointer casts for strict-aliasing violations.'
        ),
    },
}

_SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'UNKNOWN': 4}


def _parse_afl_crash_signal(filename: str) -> int:
    """Extract the signal number from an AFL++ crash filename (e.g. id:...,sig:11,...)."""
    m = re.search(r'sig:(\d+)', filename)
    return int(m.group(1)) if m else 0


def _replay_crash(binary_path: str, crash_file: str,
                  binary_args: list, timeout: int = 10) -> tuple:
    """Run the binary with one crash input. Returns (returncode, signum, output)."""
    args = [a.replace('@@', crash_file) for a in binary_args]
    cmd  = [binary_path] + args
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            env={**os.environ,
                 'ASAN_OPTIONS': 'detect_leaks=0:abort_on_error=1:symbolize=1'},
        )
        rc     = r.returncode
        signum = (-rc) if rc < 0 else 0
        output = (r.stdout + r.stderr)[:4096]
        return rc, signum, output
    except subprocess.TimeoutExpired:
        return -1, 0, '<timeout — possible hang>'
    except Exception as e:
        return -1, 0, str(e)


def _classify_crash(signum: int, filename_signal: int, output: str) -> dict:
    """Classify a crash. ASAN output takes priority over signal number."""
    out_lower = output.lower()
    for pattern, info in _CRASH_CLASSES.items():
        if pattern in out_lower:
            return {**info, 'detection': f'ASAN: {pattern}'}
    sig = signum or filename_signal
    if sig in _SIGNAL_CLASSES:
        return {**_SIGNAL_CLASSES[sig],
                'detection': _SIGNAL_NAMES.get(sig, f'signal {sig}')}
    return {
        'severity':       'UNKNOWN',
        'vuln_class':     'Unknown',
        'exploitability': 'Needs manual investigation',
        'why':  ('The crash could not be automatically classified. '
                 'The binary may have exited abnormally without a recognisable signal.'),
        'next': ('Replay manually: gdb -ex run --args <binary> <crash_input_path>'),
        'detection': f'exit:{signum or filename_signal or "?"}',
    }


def triage_crashes(crash_dir: str, binary_path: str) -> list:
    """Replay every crash input, classify each one, return records sorted by severity."""
    crash_path = Path(crash_dir)
    if not crash_path.is_dir():
        return []
    crash_files = sorted(
        f for f in crash_path.iterdir()
        if f.is_file() and f.name != 'README.txt'
    )
    if not crash_files:
        return []

    agent       = FuzzingCoordinatorAgent()
    binary_args = agent._get_binary_args(binary_path) or ['@@']

    records = []
    for cf in crash_files:
        fn_sig          = _parse_afl_crash_signal(cf.name)
        rc, sig, output = _replay_crash(binary_path, str(cf), binary_args)
        cls             = _classify_crash(sig, fn_sig, output)
        records.append({
            'file':           cf.name,
            'path':           str(cf),
            'rc':             rc,
            'signal':         sig or fn_sig,
            'output_snippet': output[:300].strip(),
            **cls,
        })

    records.sort(key=lambda r: _SEVERITY_ORDER.get(r['severity'], 99))
    return records


def _wrap_text(text: str, max_w: int, indent: int = 18) -> list:
    """Word-wrap text into lines of max_w chars; continuation lines are indented."""
    words, lines, line = text.split(), [], ''
    for word in words:
        if len(line) + len(word) + 1 > max_w:
            lines.append(line.rstrip())
            line = ' ' * indent + word + ' '
        else:
            line += word + ' '
    if line.strip():
        lines.append(line.rstrip())
    return lines


def show_crash_triage(crash_dir: str, binary_path: str) -> None:
    """Display a formatted crash triage report for all crash inputs in crash_dir."""
    status("Triaging crash inputs ...", 'run')
    records = triage_crashes(crash_dir, binary_path)
    if not records:
        status("No crash inputs to triage", 'info')
        return

    section(f"CRASH TRIAGE  —  {os.path.basename(binary_path)}")

    # ── Summary counts ─────────────────────────────────────────────────────────
    from collections import Counter
    sev_counts = Counter(r['severity'] for r in records)
    summary_lines = [
        f"{DIM}Total crashes triaged  {RESET}  {BOLD}{len(records)}{RESET}",
        '',
    ]
    for sev, color in [('CRITICAL', BRIGHT_RED), ('HIGH', RED),
                       ('MEDIUM', YELLOW), ('LOW', GREEN), ('UNKNOWN', DIM)]:
        if sev_counts[sev]:
            summary_lines.append(
                f"{DIM}{sev:<10}{RESET}  {color}{BOLD}{sev_counts[sev]}{RESET}"
            )
    box('TRIAGE SUMMARY', summary_lines)

    # ── Per-crash detail cards ─────────────────────────────────────────────────
    max_w = W - 20
    for i, r in enumerate(records, 1):
        sev   = r['severity']
        sc    = {'CRITICAL': BRIGHT_RED, 'HIGH': RED,
                 'MEDIUM': YELLOW, 'LOW': GREEN}.get(sev, DIM)
        fname = r['file'] if len(r['file']) <= 55 else '...' + r['file'][-52:]

        lines = [
            f"{DIM}Input file     {RESET}  {DIM}{fname}{RESET}",
            f"{DIM}Detection      {RESET}  {sc}{r['detection']}{RESET}",
            f"{DIM}Severity       {RESET}  {sc}{BOLD}{sev}{RESET}",
            f"{DIM}Vuln class     {RESET}  {BOLD}{r['vuln_class']}{RESET}",
            f"{DIM}Exploitability {RESET}  {sc}{r['exploitability']}{RESET}",
            '',
        ]

        for label, key in [('Why it matters', 'why'), ('Next step', 'next')]:
            wrapped = _wrap_text(r[key], max_w)
            if wrapped:
                lines.append(f"{DIM}{label:<14}{RESET}  {wrapped[0]}")
                lines.extend(wrapped[1:])
            lines.append('')

        while lines and lines[-1] == '':
            lines.pop()

        print()
        box(f"CRASH {i} / {len(records)}", lines)

    # ── Compact summary table ──────────────────────────────────────────────────
    print()
    rows = []
    for r in records:
        sc    = {'CRITICAL': BRIGHT_RED, 'HIGH': RED,
                 'MEDIUM': YELLOW, 'LOW': GREEN}.get(r['severity'], DIM)
        fname = r['file'][:28] + '…' if len(r['file']) > 28 else r['file']
        rows.append([
            fname,
            (r['severity'], sc),
            r['vuln_class'][:24],
            r['exploitability'][:28],
        ])
    print_table(
        ['Input File', 'Severity', 'Vuln Class', 'Exploitability'],
        rows, [30, 10, 26, 30],
    )

    print()
    status(f"Crash inputs dir  {DIM}{crash_dir}{RESET}", 'info')
    status("Replay any crash:  gdb -ex run --args <binary> <crash_input_path>", 'info')


# ── BinDiff display ───────────────────────────────────────────────────────────

def _show_diff_results(changes: list, report_dir: str) -> None:
    if not changes:
        status("No changes detected between the two binaries", 'info')
        return

    modified = [c for c in changes if c.change_type == 'modified']
    added    = [c for c in changes if c.change_type == 'added']
    removed  = [c for c in changes if c.change_type == 'removed']
    mem_risk = [c for c in changes if c.is_memory_related]
    par_risk = [c for c in changes if c.is_parsing_related]

    lines = [
        f"{DIM}Total changes   {RESET}  {BOLD}{len(changes)}{RESET}",
        f"{DIM}Modified        {RESET}  {YELLOW}{len(modified)}{RESET}",
        f"{DIM}Added           {RESET}  {GREEN}{len(added)}{RESET}",
        f"{DIM}Removed         {RESET}  {RED}{len(removed)}{RESET}",
        '',
        f"{DIM}Memory-related  {RESET}  {(BRIGHT_RED if mem_risk else GREEN)}{len(mem_risk)}{RESET}",
        f"{DIM}Parsing-related {RESET}  {(YELLOW if par_risk else GREEN)}{len(par_risk)}{RESET}",
        '',
        f"{DIM}Report          {RESET}  {DIM}{report_dir}/bindiff_analysis.json{RESET}",
    ]
    print()
    box('BINDIFF SUMMARY', lines)

    # Top modified functions (most changed first)
    top = sorted(modified, key=lambda c: c.similarity_score)[:15]
    if top:
        print()
        rows = []
        for c in top:
            sc = BRIGHT_RED if c.similarity_score < 0.5 else YELLOW if c.similarity_score < 0.8 else GREEN
            name = c.function_name if len(c.function_name) <= 38 else c.function_name[:35] + '...'
            mem  = f"{RED}Y{RESET}" if c.is_memory_related  else f"{DIM}N{RESET}"
            par  = f"{YELLOW}Y{RESET}" if c.is_parsing_related else f"{DIM}N{RESET}"
            rows.append([name, (f"{c.similarity_score:.3f}", sc),
                         f"{c.cfg_complexity_delta:+d}", mem, par])
        print_table(['Function', 'Similarity', 'CFGδ', 'Mem', 'Parse'],
                    rows, [40, 10, 6, 4, 5])

    # Added
    if added:
        print()
        status(f"{len(added)} functions added in updated binary", 'info')
        for c in added[:6]:
            name = c.function_name[:65] if len(c.function_name) <= 65 else c.function_name[:62] + '...'
            flag = f"  {RED}[MEM]{RESET}" if c.is_memory_related else ''
            status(f"  + {GREEN}{name}{RESET}{flag}", 'ok')
        if len(added) > 6:
            status(f"  ... and {len(added)-6} more  (see JSON report)", 'info')

    # Removed
    if removed:
        print()
        status(f"{len(removed)} functions removed from baseline", 'info')
        for c in removed[:6]:
            name = c.function_name[:65] if len(c.function_name) <= 65 else c.function_name[:62] + '...'
            flag = f"  {RED}[MEM]{RESET}" if c.is_memory_related else ''
            status(f"  - {RED}{name}{RESET}{flag}", 'warn')
        if len(removed) > 6:
            status(f"  ... and {len(removed)-6} more  (see JSON report)", 'info')


# ── Workflow 1: Standalone Fuzz ───────────────────────────────────────────────

def fuzz_workflow(config: dict, workspace: str) -> None:
    """Fuzz a single binary: pick binary → seeds → mode → duration → launch."""

    # ── Step 1: pick binary ───────────────────────────────────────────────────
    all_bins = list_all_binaries(config)
    if not all_bins:
        status("No binaries found in config.json", 'err')
        return

    _menu('SELECT BINARY TO FUZZ',
          [(f"{BOLD}{b['label']}{RESET}", b['path']) for b in all_bins])
    choice = _pick('Select binary', 0, len(all_bins))
    if choice <= 0:
        return

    binary = all_bins[choice - 1]
    if not verify_binary_exists(binary['path']):
        status(f"Binary not found: {binary['path']}", 'err')
        return
    status(f"Binary: {BOLD}{binary['label']}{RESET}", 'ok')

    # ── Step 2: pick seed corpus ──────────────────────────────────────────────
    seed_dirs = discover_seed_dirs()
    seed_items = [(f"{BOLD}{s['label']}{RESET}", s['path']) for s in seed_dirs]
    seed_items.append((f"{YELLOW}Custom path ...{RESET}", ''))
    _menu('SELECT SEED CORPUS', seed_items)

    s_choice = _pick('Select corpus', 0, len(seed_items))
    if s_choice <= 0:
        return

    if s_choice == len(seed_items):      # custom path
        corpus_dir = input(f"  {BOLD}Enter corpus path{RESET}: ").strip()
        if not corpus_dir or not os.path.isdir(corpus_dir):
            status("Invalid corpus path", 'err')
            return
    else:
        corpus_dir = seed_dirs[s_choice - 1]['path']

    status(f"Corpus: {DIM}{corpus_dir}{RESET}", 'ok')

    # ── Step 3: pick fuzzing mode ─────────────────────────────────────────────
    _menu('FUZZING MODE', [
        (f"{GREEN}Baseline AFL++{RESET}",
         "Direct QEMU mode — no MARL, fastest startup"),
        (f"{CYAN}MARL-Guided AFL++{RESET}",
         "RL agent selects power schedule based on past results"),
    ])
    f_choice = _pick('Select mode', 0, 2)
    if f_choice <= 0:
        return

    # ── Step 4: duration ──────────────────────────────────────────────────────
    default_t = config['fuzzing']['afl_config'].get('duration_seconds', 3600)
    raw_t = input(f"  {BOLD}Duration (seconds){RESET} {DIM}[default: {default_t}]{RESET}: ").strip()
    timeout = int(raw_t) if raw_t.isdigit() else default_t

    # ── Launch ────────────────────────────────────────────────────────────────
    section(f"FUZZING  {binary['label'].upper()}")

    if f_choice == 1:
        run_baseline_afl(binary['path'], corpus_dir, workspace, timeout)

    else:  # MARL-guided
        agent = FuzzingCoordinatorAgent()
        model_path = os.path.join(workspace, 'models', 'fuzzing_agent.pkl')
        if os.path.exists(model_path):
            agent.load_model(model_path)
            status("Loaded MARL Q-table from previous run", 'ok')
        else:
            status("No saved Q-table found — starting fresh", 'info')

        out_dir = os.path.join(workspace, 'standalone_fuzz')
        os.makedirs(out_dir, exist_ok=True)

        status("Running MARL-guided fuzzing campaign ...", 'run')
        result = agent.coordinate_fuzzing(binary['path'], corpus_dir,
                                          out_dir, [], timeout=timeout)

        cc = BRIGHT_RED if result.unique_crashes > 0 else GREEN
        print()
        box('MARL FUZZ RESULTS', [
            f"{DIM}Binary    {RESET}  {os.path.basename(binary['path'])}",
            f"{DIM}Campaign  {RESET}  {result.campaign_id}",
            '',
            f"{DIM}Execs     {RESET}  {result.total_execs:,}",
            f"{DIM}Crashes   {RESET}  {cc}{BOLD}{result.unique_crashes}{RESET}",
            f"{DIM}Hangs     {RESET}  {result.hangs}",
            f"{DIM}Coverage  {RESET}  {CYAN}{result.coverage_percentage:.2f}%{RESET}",
        ])

        # Persist updated Q-table
        models_dir = os.path.join(workspace, 'models')
        os.makedirs(models_dir, exist_ok=True)
        try:
            agent.save_model(os.path.join(models_dir, 'fuzzing_agent.pkl'))
            status("MARL Q-table saved", 'ok')
        except Exception as e:
            status(f"Could not save Q-table: {e}", 'warn')

        # ── Generate chart ────────────────────────────────────────────────────
        record = {
            'binary':   os.path.basename(binary['path']),
            'version':  binary.get('version', '?'),
            'execs':    result.total_execs,
            'crashes':  result.unique_crashes,
            'hangs':    result.hangs,
            'coverage': result.coverage_percentage,
        }
        chart_dir  = os.path.join(out_dir, 'charts')
        chart_path = generate_fuzz_charts([record], chart_dir,
                                          title_prefix=f"MARL — {os.path.basename(binary['path'])} — ")
        if chart_path:
            status(f"Chart saved  {DIM}{chart_path}{RESET}", 'ok')


# ── Workflow 2: BinDiff Analysis ──────────────────────────────────────────────

def bindiff_workflow(config: dict, workspace: str) -> None:
    """Standalone BinDiff: pick a binary pair → diff → display results."""

    pairs = list(config.get('binaries', {}).keys())
    pair_items = []
    for name in pairs:
        cfg = config['binaries'][name]
        bv  = cfg['baseline'].get('version', '?')
        uv  = cfg['updated'].get('version', '?')
        pair_items.append((f"{BOLD}{name}{RESET}", f"v{bv} → v{uv}"))

    _menu('SELECT BINARY PAIR FOR DIFFING', pair_items)
    choice = _pick('Select pair', 0, len(pairs))
    if choice <= 0:
        return

    binary_name   = pairs[choice - 1]
    cfg           = config['binaries'][binary_name]
    baseline_path = cfg['baseline']['path']
    updated_path  = cfg['updated']['path']
    baseline_ver  = cfg['baseline'].get('version', '?')
    updated_ver   = cfg['updated'].get('version', '?')

    if not verify_binary_exists(baseline_path) or not verify_binary_exists(updated_path):
        status("One or both binaries not found — check config.json paths", 'err')
        return

    section(f"BINDIFF  {binary_name.upper()}  v{baseline_ver} → v{updated_ver}")
    status(f"Baseline  {DIM}{baseline_path}{RESET}", 'info')
    status(f"Updated   {DIM}{updated_path}{RESET}", 'info')
    print()
    status("Running binary diff (lief + capstone) — this may take a minute ...", 'run')

    diff_dir = os.path.join(workspace, 'bindiff_results', binary_name)
    os.makedirs(diff_dir, exist_ok=True)

    try:
        agent   = BinDiffAnalyzerAgent()
        changes = agent.analyze_binary_diff(baseline_path, updated_path, diff_dir)
        status(f"{len(changes)} structural changes found", 'ok')
        _show_diff_results(changes, diff_dir)

        # ── Generate chart ────────────────────────────────────────────────────
        chart_dir  = os.path.join(diff_dir, 'charts')
        chart_path = generate_bindiff_charts(changes, binary_name, chart_dir)
        if chart_path:
            status(f"Chart saved  {DIM}{chart_path}{RESET}", 'ok')
    except Exception as e:
        status(f"BinDiff failed: {e}", 'err')
        logger.error(f"BinDiff error: {e}", exc_info=True)


# ── Workflow 3: Full MARL Forecast ────────────────────────────────────────────

def _marl_binary_menu(config: dict, workspace: str) -> None:
    available = list(config['binaries'].keys())
    all_idx   = len(available) + 1

    print(f"┌{'─' * (W - 2)}┐")
    print(f"│{_pad(f'  {BOLD}SELECT BINARY PAIR{RESET}', W - 2)}│")
    print(f"├{'─' * 6}┬{'─' * (W - 9)}┤")
    for i, name in enumerate(available, 1):
        print(f"│{_pad(f'  {CYAN}[{i}]{RESET} ', 6)}│{_pad(f'  {BOLD}{name}{RESET}', W - 9)}│")
    print(f"├{'─' * 6}┼{'─' * (W - 9)}┤")
    print(f"│{_pad(f'  {CYAN}[{all_idx}]{RESET} ', 6)}│{_pad(f'  {BOLD}Analyze ALL binaries{RESET}', W - 9)}│")
    print(f"│{_pad(f'  {DIM}[0]{RESET} ', 6)}│{_pad(f'  {DIM}Back{RESET}', W - 9)}│")
    print(f"└{'─' * 6}┴{'─' * (W - 9)}┘")
    print(f"\n  {DIM}Workspace → {workspace}{RESET}\n")
    return available

def _forecast_to_chart_record(name: str, forecast) -> dict:
    """Convert a VulnerabilityForecast into the dict expected by generate_marl_dashboard."""
    fd = forecast.fuzzing_divergence or {}
    return {
        'binary':           name,
        'risk':             forecast.risk_category,
        'score':            forecast.combined_risk_score,
        'structural_score': forecast.structural_risk_score,
        'behavioral_score': forecast.behavioral_risk_score,
        'dependency_score': forecast.dependency_risk_score,
        'baseline_crashes': fd.get('baseline_crashes', 0),
        'updated_crashes':  fd.get('updated_crashes', 0),
        'baseline_cov':     fd.get('baseline_coverage', 0),
        'updated_cov':      fd.get('updated_coverage', 0),
        'changed_funcs':    len(forecast.changed_functions),
        'memory_funcs':     sum(1 for c in forecast.changed_functions if c.is_memory_related),
        'parsing_funcs':    sum(1 for c in forecast.changed_functions if c.is_parsing_related),
        # Private key — fuzz details for per-binary fuzz chart
        '_fuzz': {
            'baseline_execs':    fd.get('baseline_execs', 0),
            'updated_execs':     fd.get('updated_execs', 0),
            'baseline_crashes':  fd.get('baseline_crashes', 0),
            'updated_crashes':   fd.get('updated_crashes', 0),
            'baseline_hangs':    fd.get('baseline_hangs', 0),
            'updated_hangs':     fd.get('updated_hangs', 0),
            'baseline_coverage': fd.get('baseline_coverage', 0),
            'updated_coverage':  fd.get('updated_coverage', 0),
        },
    }


def marl_workflow(config: dict, workspace: str) -> None:
    """Full MARL forecast pipeline: BinDiff + fuzz baseline + fuzz updated + risk score."""
    status("Initialising MARL agents ...", 'run')
    forecaster = MARLVulnerabilityForecaster(workspace_dir=workspace)
    status("Agents ready", 'ok')

    model_dir = config['marl_config']['model_persistence']['model_directory']
    if config['marl_config']['model_persistence'].get('load_pretrained', False):
        if os.path.exists(model_dir):
            status("Loading pre-trained agent models ...")
            forecaster.load_models()
            status("Models loaded", 'ok')
        else:
            status("No pre-trained models found — starting fresh", 'warn')

    print()
    available = _marl_binary_menu(config, workspace)
    choice    = _pick('Select', 0, len(available) + 1)
    if choice < 0:
        return
    if choice == 0:
        return

    results       = []   # summary rows for table
    chart_records = []   # richer dicts for dashboard chart
    all_changes   = {}   # binary_name → list[StructuralChange]

    if choice == len(available) + 1:
        section(f"BATCH ANALYSIS  —  All {len(available)} Binaries")
        for name in available:
            forecast = _run_marl_pair(name, config, forecaster)
            if forecast:
                results.append({'binary': name,
                                'risk':   forecast.risk_category,
                                'score':  forecast.combined_risk_score})
                chart_records.append(_forecast_to_chart_record(name, forecast))
                all_changes[name] = forecast.changed_functions
        if results:
            print()
            rows = []
            for r in results:
                rc  = risk_color(r['risk'])
                bar = score_bar(r['score'], width=20)
                rows.append([r['binary'], (r['risk'].upper(), rc),
                             f"{r['score']:5.2f}", bar])
            print_table(['Binary', 'Risk', 'Score', 'Score Bar'],
                        rows, [14, 10, 7, 22])

    elif 1 <= choice <= len(available):
        forecast = _run_marl_pair(available[choice - 1], config, forecaster)
        if forecast:
            name = available[choice - 1]
            results.append({'binary': name,
                            'risk':   forecast.risk_category,
                            'score':  forecast.combined_risk_score})
            chart_records.append(_forecast_to_chart_record(name, forecast))
            all_changes[name] = forecast.changed_functions

    # Save models
    if results and config['marl_config']['model_persistence'].get('save_interval'):
        print()
        status("Saving agent models ...")
        try:
            forecaster.save_models()
            status(f"Models saved  {DIM}{workspace}/models{RESET}", 'ok')
        except Exception as e:
            status(f"Failed to save models: {e}", 'err')

    # ── Generate charts ───────────────────────────────────────────────────────
    if chart_records:
        chart_dir = os.path.join(workspace, 'charts')
        print()
        status("Generating charts ...", 'run')

        # Per-binary BinDiff chart
        for name, changes in all_changes.items():
            if changes:
                bd_dir  = os.path.join(chart_dir, name)
                bd_path = generate_bindiff_charts(changes, name, bd_dir)
                if bd_path:
                    status(f"BinDiff chart  {DIM}{bd_path}{RESET}", 'ok')

        # Combined fuzzing chart
        fuzz_recs = []
        for r in chart_records:
            fd = r.get('_fuzz', {})
            for version in ('baseline', 'updated'):
                fuzz_recs.append({
                    'binary':   r['binary'],
                    'version':  version,
                    'execs':    fd.get(f'{version}_execs', 0),
                    'crashes':  fd.get(f'{version}_crashes', 0),
                    'hangs':    fd.get(f'{version}_hangs', 0),
                    'coverage': fd.get(f'{version}_coverage', 0),
                })
        fuzz_path = generate_fuzz_charts(fuzz_recs, chart_dir,
                                         title_prefix='MARL — ')
        if fuzz_path:
            status(f"Fuzz chart     {DIM}{fuzz_path}{RESET}", 'ok')

        # Full dashboard (only meaningful with ≥1 binary)
        dash_path = generate_marl_dashboard(chart_records, chart_dir)
        if dash_path:
            status(f"Dashboard      {DIM}{dash_path}{RESET}", 'ok')

    print()
    print(f"{'─' * W}")
    if results:
        n = len(results)
        status(f"{GREEN}{BOLD}{n} analysis{'es' if n > 1 else ''} complete.{RESET}"
               f"  {DIM}Results → {workspace}/forecast_results.json{RESET}", 'ok')
    else:
        status("No analyses completed. Check binary paths in config.json.", 'warn')
    print(f"  {DIM}Full log → production.log{RESET}")
    print(f"{'─' * W}\n")


def _run_marl_pair(binary_name: str, config: dict, forecaster) -> object:
    """Run the full MARL pipeline for one binary pair."""
    print()
    section(f"ANALYZING  {binary_name.upper()}")

    bc = config['binaries'].get(binary_name)
    if not bc:
        status(f"'{binary_name}' not in config.json", 'err')
        return None

    baseline_path = bc['baseline']['path']
    updated_path  = bc['updated']['path']
    baseline_ver  = bc['baseline'].get('version', '?')
    updated_ver   = bc['updated'].get('version', '?')
    corpus_path   = (config['fuzzing']['corpus_directories']['onnx']
                     if 'onnx' in binary_name.lower()
                     else config['fuzzing']['corpus_directories']['llama'])

    status("Verifying binaries ...")
    if not verify_binary_exists(baseline_path):
        status(f"Baseline not found: {baseline_path}", 'err')
        return None
    status(f"Baseline  v{baseline_ver}  {DIM}{baseline_path}{RESET}", 'ok')

    if not verify_binary_exists(updated_path):
        status(f"Updated not found: {updated_path}", 'err')
        return None
    status(f"Updated   v{updated_ver}  {DIM}{updated_path}{RESET}", 'ok')

    print()
    status("Verifying corpus ...")
    if not verify_corpus_exists(corpus_path):
        status(f"Corpus not ready: {corpus_path}", 'err')
        return None
    files = list(Path(corpus_path).glob("*"))
    status(f"{len(files)} files found  {DIM}{corpus_path}{RESET}", 'ok')

    print()
    status(f"Starting MARL forecast  {DIM}(v{baseline_ver} → v{updated_ver}){RESET}")
    try:
        forecast = forecaster.forecast_vulnerability(
            baseline_path, updated_path, corpus_path,
            config={'fuzz_timeout': config['fuzzing']['afl_config'].get('duration_seconds', 3600)}
        )
        status("Forecast complete", 'ok')
        print()
        print_forecast(forecast, binary_name)
        print()
        print_recommendations(forecast.recommendations)

        # ── Crash triage for both binary versions ─────────────────────────────
        marl_ws = Path(str(forecaster.workspace))
        for fuzz_subdir, bin_path, label in [
            ('fuzzing_baseline', baseline_path, 'Baseline'),
            ('fuzzing_updated',  updated_path,  'Updated'),
        ]:
            crash_dirs = sorted(
                (marl_ws / fuzz_subdir).glob('*/default/crashes')
            )
            for cd in crash_dirs:
                crash_files = [f for f in cd.iterdir()
                               if f.is_file() and f.name != 'README.txt']
                if crash_files:
                    status(f"{label}: {len(crash_files)} crash(es) found"
                           f"  {DIM}{cd}{RESET}", 'warn')
                    show_crash_triage(str(cd), bin_path)

        return forecast
    except Exception as e:
        status(f"Forecast failed: {e}", 'err')
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return None


# ── CVE Lookup ────────────────────────────────────────────────────────────────

# Maps config binary names to NVD keyword search terms
CVE_KEYWORD_MAP: dict = {
    'llama':        'llama.cpp',
    'llama-server': 'llama.cpp',
    'llama-bench':  'llama.cpp',
    'onnx':         'onnxruntime',
}

NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'


def _nvd_search(keyword: str, results_per_page: int = 20) -> list:
    """Query NVD API v2 for CVEs matching keyword. Returns list of CVE dicts."""
    params = urllib.parse.urlencode({
        'keywordSearch':  keyword,
        'resultsPerPage': results_per_page,
    })
    url = f"{NVD_API}?{params}"
    req = urllib.request.Request(url, headers={'User-Agent': 'BinFuzz/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
            return data.get('vulnerabilities', [])
    except urllib.error.URLError as e:
        logger.error(f"NVD API request failed: {e}")
        return []
    except (json.JSONDecodeError, KeyError) as e:
        logger.error(f"NVD API response parse error: {e}")
        return []


def _parse_cve(entry: dict) -> dict:
    """Extract relevant fields from a raw NVD vulnerability entry."""
    cve = entry.get('cve', {})
    cve_id = cve.get('id', 'N/A')
    published = cve.get('published', '')[:10]   # YYYY-MM-DD

    # English description
    desc = next(
        (d['value'] for d in cve.get('descriptions', []) if d.get('lang') == 'en'),
        'No description available.'
    )

    # CVSS score — prefer v3.1, fall back to v3.0, then v2
    metrics = cve.get('metrics', {})
    score, severity = None, 'UNKNOWN'
    for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
        bucket = metrics.get(key, [])
        if bucket:
            cvss_data = bucket[0].get('cvssData', {})
            score    = cvss_data.get('baseScore')
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
            break

    return {
        'id':        cve_id,
        'published': published,
        'score':     score,
        'severity':  severity.upper() if severity else 'UNKNOWN',
        'desc':      desc,
    }


def _severity_color(severity: str) -> str:
    return {
        'CRITICAL': BRIGHT_RED,
        'HIGH':     RED,
        'MEDIUM':   YELLOW,
        'LOW':      GREEN,
    }.get(severity.upper(), DIM)


def _display_cve_results(parsed: list, binary_name: str, version: str) -> None:
    if not parsed:
        status(f"No CVEs found for {binary_name} v{version}", 'info')
        return

    print()
    rows = []
    for c in parsed:
        sc   = _severity_color(c['severity'])
        score_str = f"{c['score']:.1f}" if c['score'] is not None else ' N/A'
        # Truncate description to fit terminal
        desc = c['desc'][:52] + '…' if len(c['desc']) > 52 else c['desc']
        rows.append([
            c['id'],
            c['published'],
            (c['severity'], sc),
            score_str,
            desc,
        ])
    print_table(
        ['CVE ID', 'Published', 'Severity', 'Score', 'Description'],
        rows,
        [18, 10, 8, 5, 54],
    )


def cve_lookup_workflow(config: dict, workspace: str) -> None:
    """Look up known CVEs for all configured binaries via the NVD API."""

    all_bins = list_all_binaries(config)
    if not all_bins:
        status("No binaries found in config.json", 'err')
        return

    # ── Pick: single binary or all ────────────────────────────────────────────
    items = [(f"{BOLD}{b['label']}{RESET}", b['path']) for b in all_bins]
    items.append((f"{CYAN}Check ALL binaries{RESET}", ''))
    _menu('CVE LOOKUP — SELECT TARGET', items)

    choice = _pick('Select', 0, len(items))
    if choice <= 0:
        return

    if choice == len(items):
        targets = all_bins
    else:
        targets = [all_bins[choice - 1]]

    # ── Query NVD for each unique (binary_name, version) pair ─────────────────
    # Deduplicate: same project may appear as baseline + updated with same keyword
    seen_queries: set = set()
    all_results:  dict = {}   # (binary_name, version) → list[cve_dict]

    section('CVE LOOKUP  —  NVD API v2')

    for b in targets:
        keyword = CVE_KEYWORD_MAP.get(b['name'], b['name'])
        key     = (keyword, b['version'])

        if key in seen_queries:
            # Reuse cached result
            all_results[(b['name'], b['version'])] = all_results.get(
                (b['name'], b['version']), [])
            continue
        seen_queries.add(key)

        status(f"Querying NVD  {DIM}keyword={keyword!r}  version={b['version']}{RESET}", 'run')
        raw    = _nvd_search(keyword)
        parsed = [_parse_cve(e) for e in raw]

        # Filter: keep CVEs that mention the version string (loose match)
        version_filtered = [
            c for c in parsed
            if b['version'] in c['desc'] or not b['version']
        ]
        # If nothing matches the version fall back to all results for the keyword
        final = version_filtered if version_filtered else parsed

        all_results[(b['name'], b['version'])] = final
        status(f"Found {len(final)} CVE(s) for {b['name']} v{b['version']}", 'ok')

        _display_cve_results(final, b['name'], b['version'])

    # ── Save to workspace ─────────────────────────────────────────────────────
    if all_results:
        out_dir = os.path.join(workspace, 'cve_results')
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, f"cve_lookup_{int(time.time())}.json")
        serialisable = {
            f"{name}_v{ver}": cves
            for (name, ver), cves in all_results.items()
        }
        with open(out_path, 'w') as f:
            json.dump(serialisable, f, indent=2)
        print()
        status(f"Results saved  {DIM}{out_path}{RESET}", 'ok')

    # ── Summary box ───────────────────────────────────────────────────────────
    total = sum(len(v) for v in all_results.values())
    critical = sum(
        1 for cves in all_results.values()
        for c in cves if c['severity'] in ('CRITICAL', 'HIGH')
    )
    lines = [
        f"{DIM}Binaries checked  {RESET}  {len(all_results)}",
        f"{DIM}Total CVEs found  {RESET}  {BOLD}{total}{RESET}",
        f"{DIM}Critical / High   {RESET}  "
        f"{(BRIGHT_RED if critical > 0 else GREEN)}{BOLD}{critical}{RESET}",
    ]
    print()
    box('CVE LOOKUP SUMMARY', lines)


# ── Workflow 5: Crash Triage ──────────────────────────────────────────────────

def _discover_crash_dirs(workspace: str) -> list:
    """Walk the workspace and find every AFL++ crash directory that has inputs."""
    ws   = Path(workspace)
    hits = []
    for crash_dir in sorted(ws.rglob('crashes')):
        if not crash_dir.is_dir():
            continue
        files = [f for f in crash_dir.iterdir()
                 if f.is_file() and f.name != 'README.txt']
        if not files:
            continue
        # Try to infer a human-readable label from the path structure
        parts = crash_dir.parts
        try:
            # e.g.  .../fuzzing_baseline/<campaign_id>/default/crashes
            #        .../standalone_fuzz/<ts>/default/crashes
            label_parts = list(parts[parts.index(ws.name) + 1:])
            label = ' / '.join(label_parts[:-2])   # drop default/crashes
        except (ValueError, IndexError):
            label = str(crash_dir.relative_to(ws))
        hits.append({
            'label':     label,
            'crash_dir': str(crash_dir),
            'count':     len(files),
        })
    return hits


def triage_workflow(config: dict, workspace: str) -> None:
    """Menu-driven crash triage: pick a crash dir → pick a binary → show report."""

    # ── Step 1: find crash dirs ───────────────────────────────────────────────
    crash_dirs = _discover_crash_dirs(workspace)

    if not crash_dirs:
        status("No crash inputs found in workspace yet — run some fuzzing first", 'warn')
        status(f"Workspace: {DIM}{workspace}{RESET}", 'info')
        return

    items = [
        (f"{BRIGHT_RED}{BOLD}{d['count']} crash(es){RESET}  {d['label']}", d['crash_dir'])
        for d in crash_dirs
    ]
    items.append((f"{YELLOW}Enter path manually ...{RESET}", ''))
    _menu('SELECT CRASH DIRECTORY', items)

    choice = _pick('Select', 0, len(items))
    if choice <= 0:
        return

    if choice == len(items):
        crash_dir = input(f"  {BOLD}Crash directory path{RESET}: ").strip()
        if not crash_dir or not os.path.isdir(crash_dir):
            status("Invalid path", 'err')
            return
    else:
        crash_dir = crash_dirs[choice - 1]['crash_dir']

    status(f"Crash dir: {DIM}{crash_dir}{RESET}", 'ok')

    # ── Step 2: pick binary ───────────────────────────────────────────────────
    all_bins = list_all_binaries(config)
    _menu('SELECT BINARY THAT PRODUCED THESE CRASHES',
          [(f"{BOLD}{b['label']}{RESET}", b['path']) for b in all_bins])
    b_choice = _pick('Select binary', 0, len(all_bins))
    if b_choice <= 0:
        return

    binary = all_bins[b_choice - 1]
    if not verify_binary_exists(binary['path']):
        status(f"Binary not found: {binary['path']}", 'err')
        return

    # ── Step 3: triage ────────────────────────────────────────────────────────
    section(f"CRASH TRIAGE  —  {binary['label'].upper()}")
    show_crash_triage(crash_dir, binary['path'])


# ── Batch (unattended) mode ───────────────────────────────────────────────────

def run_batch(config: dict, workspace: str) -> None:
    """Non-interactive: run full MARL forecast on every binary pair in config.json.
    Each binary is wrapped in a try/except so one failure never stops the rest.
    Results are written to <workspace>/batch_summary.json and production.log.
    """
    logger.info("=" * 60)
    logger.info("BATCH MODE START")
    logger.info("=" * 60)

    section("BATCH MODE  —  Full MARL Forecast on All Binaries")

    available = list(config.get('binaries', {}).keys())
    if not available:
        status("No binaries found in config.json", 'err')
        logger.error("Batch aborted — no binaries in config")
        return

    status(f"{len(available)} binary pair(s) queued: {', '.join(available)}", 'info')

    status("Initialising MARL agents ...", 'run')
    try:
        forecaster = MARLVulnerabilityForecaster(workspace_dir=workspace)
    except Exception as e:
        status(f"Failed to initialise MARL forecaster: {e}", 'err')
        logger.error(f"MARL init error: {e}", exc_info=True)
        return
    status("Agents ready", 'ok')

    results       = []
    chart_records = []
    all_changes   = {}
    failed        = []

    for name in available:
        logger.info(f"--- Starting analysis: {name} ---")
        try:
            forecast = _run_marl_pair(name, config, forecaster)
            if forecast:
                rec = {
                    'binary': name,
                    'risk':   forecast.risk_category,
                    'score':  forecast.combined_risk_score,
                }
                results.append(rec)
                chart_records.append(_forecast_to_chart_record(name, forecast))
                all_changes[name] = forecast.changed_functions
                logger.info(f"{name}: DONE  risk={forecast.risk_category}  "
                            f"score={forecast.combined_risk_score:.2f}")
            else:
                failed.append(name)
                logger.warning(f"{name}: analysis returned no forecast "
                               "(check binary paths and corpus in config.json)")
        except Exception as e:
            failed.append(name)
            status(f"Unhandled error for {name}: {e}", 'err')
            logger.error(f"Batch error [{name}]: {e}", exc_info=True)

    # ── Save agent models ─────────────────────────────────────────────────────
    if results:
        try:
            forecaster.save_models()
            status(f"Models saved  {DIM}{workspace}/models{RESET}", 'ok')
        except Exception as e:
            status(f"Could not save models: {e}", 'warn')
            logger.warning(f"Model save error: {e}")

    # ── Generate charts ───────────────────────────────────────────────────────
    if chart_records:
        chart_dir = os.path.join(workspace, 'charts')
        status("Generating charts ...", 'run')
        for name, changes in all_changes.items():
            if changes:
                try:
                    bd_dir  = os.path.join(chart_dir, name)
                    bd_path = generate_bindiff_charts(changes, name, bd_dir)
                    if bd_path:
                        status(f"BinDiff chart  {DIM}{bd_path}{RESET}", 'ok')
                except Exception as e:
                    logger.warning(f"Chart error [{name}]: {e}")

        fuzz_recs = []
        for r in chart_records:
            fd = r.get('_fuzz', {})
            for version in ('baseline', 'updated'):
                fuzz_recs.append({
                    'binary':   r['binary'],
                    'version':  version,
                    'execs':    fd.get(f'{version}_execs', 0),
                    'crashes':  fd.get(f'{version}_crashes', 0),
                    'hangs':    fd.get(f'{version}_hangs', 0),
                    'coverage': fd.get(f'{version}_coverage', 0),
                })
        try:
            fuzz_path = generate_fuzz_charts(fuzz_recs, chart_dir,
                                             title_prefix='BATCH — ')
            if fuzz_path:
                status(f"Fuzz chart     {DIM}{fuzz_path}{RESET}", 'ok')
        except Exception as e:
            logger.warning(f"Fuzz chart error: {e}")

        try:
            dash_path = generate_marl_dashboard(chart_records, chart_dir)
            if dash_path:
                status(f"Dashboard      {DIM}{dash_path}{RESET}", 'ok')
        except Exception as e:
            logger.warning(f"Dashboard chart error: {e}")

    # ── Write batch summary JSON ──────────────────────────────────────────────
    summary = {
        'timestamp':   time.strftime('%Y-%m-%dT%H:%M:%S'),
        'completed':   results,
        'failed':      failed,
        'total':       len(available),
        'success':     len(results),
        'fail_count':  len(failed),
    }
    summary_path = os.path.join(workspace, 'batch_summary.json')
    try:
        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)
        status(f"Summary saved  {DIM}{summary_path}{RESET}", 'ok')
    except Exception as e:
        logger.error(f"Could not write batch summary: {e}")

    # ── Final table ───────────────────────────────────────────────────────────
    print()
    print(f"{'─' * W}")
    if results:
        rows = []
        for r in results:
            rc  = risk_color(r['risk'])
            bar = score_bar(r['score'], width=20)
            rows.append([r['binary'], (r['risk'].upper(), rc),
                         f"{r['score']:5.2f}", bar])
        print_table(['Binary', 'Risk', 'Score', 'Score Bar'],
                    rows, [16, 10, 7, 22])
    if failed:
        print()
        status(f"Skipped ({len(failed)}): {', '.join(failed)}", 'warn')
        status("Check binary paths and corpus directories in config.json", 'info')
    print()
    status(f"{GREEN}{BOLD}{len(results)}/{len(available)} analyses complete.{RESET}"
           f"  {DIM}Log → production.log{RESET}", 'ok')
    print(f"{'─' * W}\n")

    logger.info(f"BATCH MODE END — {len(results)}/{len(available)} succeeded, "
                f"{len(failed)} failed: {failed}")


# ── Main ──────────────────────────────────────────────────────────────────────

def _setup_workspace(config: dict) -> str:
    workspace = config['output']['workspace_directory']
    try:
        os.makedirs(workspace, exist_ok=True)
        if not os.access(workspace, os.W_OK):
            raise PermissionError(f"Not writable: {workspace}")
    except (PermissionError, OSError) as e:
        fallback = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                'production_workspace')
        status("Configured workspace unavailable — using local fallback", 'warn')
        logger.warning(f"Workspace fallback: {e}")
        workspace = fallback
        os.makedirs(workspace, exist_ok=True)
    return workspace


def main() -> None:
    parser = argparse.ArgumentParser(
        description='BinFuzz Production Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  Interactive:  python3 production_runner.py\n'
            '  Unattended:   nohup python3 production_runner.py --batch > batch.log 2>&1 &\n'
            '  Triage only:  python3 production_runner.py --triage /path/to/crashes '
            '--binary /path/to/binary\n'
        ),
    )
    parser.add_argument('--batch', action='store_true',
                        help='Run full MARL forecast on ALL binaries '
                             'non-interactively (no menus, safe to run with nohup)')
    parser.add_argument('--config', default='config.json',
                        help='Path to config file (default: config.json)')
    parser.add_argument(
        '--triage', metavar='CRASH_DIR',
        help='Triage crashes in an existing AFL++ crash directory without re-running '
             'fuzzing. Requires --binary to identify which binary produced the crashes.',
    )
    parser.add_argument(
        '--binary', metavar='BINARY_PATH',
        help='Binary path used with --triage.',
    )
    args = parser.parse_args()

    # ── Standalone triage mode (no config needed) ──────────────────────────────
    if args.triage:
        if not args.binary:
            print(f"{RED}error:{RESET} --triage requires --binary <path>")
            sys.exit(1)
        print_banner()
        show_crash_triage(args.triage, args.binary)
        return

    print_banner()

    status("Loading configuration ...")
    config = load_config(args.config)
    status(f"{args.config} loaded", 'ok')

    workspace = _setup_workspace(config)
    status(f"Workspace  {DIM}{workspace}{RESET}", 'info')
    print()

    if args.batch:
        run_batch(config, workspace)
        return

    MAIN_ITEMS = [
        (f"{GREEN}Fuzz Binary{RESET}",
         "Run AFL++ against a single binary with chosen seeds & mode"),
        (f"{CYAN}BinDiff Analysis{RESET}",
         "Structurally compare two binary versions (lief + capstone)"),
        (f"{YELLOW}Full MARL Forecast{RESET}",
         "Complete pipeline: BinDiff + fuzz both versions + risk score"),
        (f"{BLUE}CVE Lookup{RESET}",
         "Check configured binaries against the NVD vulnerability database"),
        (f"{BRIGHT_RED}Crash Triage{RESET}",
         "Classify & explain crashes from a previous fuzzing session"),
    ]

    while True:
        _menu('MAIN MENU', MAIN_ITEMS, back_label='Exit')
        choice = _pick('Select', 0, 5)
        if choice < 0:
            continue
        if choice == 0:
            print(f"\n  {DIM}Goodbye.{RESET}\n")
            break
        elif choice == 1:
            fuzz_workflow(config, workspace)
        elif choice == 2:
            bindiff_workflow(config, workspace)
        elif choice == 3:
            marl_workflow(config, workspace)
        elif choice == 4:
            cve_lookup_workflow(config, workspace)
        elif choice == 5:
            triage_workflow(config, workspace)


if __name__ == "__main__":
    main()
