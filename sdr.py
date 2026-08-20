#!/usr/bin/env python3
"""
SecretsDump Reporter
Parses secretsdump output (with -user-status) and generates an HTML report
and CSV file with account statistics and password reuse analysis.
"""

import argparse
import csv
import io
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path

def _get_version() -> str:
    try:
        from importlib.metadata import version
        return version("secretsdump-reporter")
    except Exception:
        pass
    # fallback: read pyproject.toml (development / source installs)
    try:
        toml = (Path(__file__).parent / "pyproject.toml").read_text()
        m = re.search(r'^version\s*=\s*"([^"]+)"', toml, re.MULTILINE)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

_VERSION = _get_version()

# --------------------------------------------------------------------------- #
#  Logo (hardcoded base64)                                                     #
# --------------------------------------------------------------------------- #

_LOGO_DATA_URI = "data:image/png;base64,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"


# --------------------------------------------------------------------------- #
#  Parsing                                                                     #
# --------------------------------------------------------------------------- #

BLANK_NT_HASH = "31d6cfe0d16ae931b73c59d7e0c089c0"
LM_DISABLED   = "aad3b435b51404eeaad3b435b51404ee"

LINE_RE = re.compile(
    r"^(?:(?P<domain>[^\\]+)\\)?(?P<username>[^:]+)"
    r":(?P<rid>\d+)"
    r":(?P<lm_hash>[0-9a-fA-F]+)"
    r":(?P<nt_hash>[0-9a-fA-F]+)"
    r":::\s*\(status=(?P<status>Enabled|Disabled)\)",
    re.IGNORECASE,
)


def is_computer(username: str) -> bool:
    return username.endswith("$")


def parse_file(path: str) -> list[dict]:
    accounts = []
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.strip()
            if not line:
                continue
            # Strip optional leading line-number prefix (e.g. "1: ")
            line = re.sub(r"^\d+:\s+", "", line)
            m = LINE_RE.match(line)
            if not m:
                continue
            d = m.groupdict()
            d["domain"] = d["domain"] or ""
            d["is_computer"] = is_computer(d["username"])
            d["enabled"] = d["status"].lower() == "enabled"
            d["lineno"] = lineno
            accounts.append(d)
    return accounts


def parse_potfile(path: str) -> dict[str, str]:
    """Return a dict mapping NT hash (lowercase) -> plaintext password."""
    cracked: dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                continue
            # hashcat potfile format: hash:password (password may contain colons)
            parts = line.split(":", 1)
            if len(parts) == 2:
                cracked[parts[0].lower()] = parts[1]
    return cracked


# --------------------------------------------------------------------------- #
#  Analysis                                                                    #
# --------------------------------------------------------------------------- #

def analyse(accounts: list[dict]) -> dict:
    enabled_users = [a for a in accounts if a["enabled"] and not a["is_computer"]]
    disabled_users = [a for a in accounts if not a["enabled"] and not a["is_computer"]]
    enabled_computers = [a for a in accounts if a["enabled"] and a["is_computer"]]
    disabled_computers = [a for a in accounts if not a["enabled"] and a["is_computer"]]

    # Group ALL accounts by NT hash to detect reuse
    hash_to_accounts: dict[str, list[dict]] = defaultdict(list)
    for a in accounts:
        hash_to_accounts[a["nt_hash"]].append(a)

    # A hash is "reused" only when more than one account shares it
    # Exclude the blank password hash — it has its own dedicated section
    reused: dict[str, list[dict]] = {
        h: accs for h, accs in hash_to_accounts.items()
        if len(accs) > 1 and h.lower() != BLANK_NT_HASH
    }

    # For each reused hash, gather the enabled accounts
    reused_enabled: dict[str, list[dict]] = {
        h: [a for a in accs if a["enabled"]]
        for h, accs in reused.items()
    }

    # Sort reused hashes by total account count descending
    sorted_reused = sorted(
        reused.items(), key=lambda kv: len(kv[1]), reverse=True
    )

    # Blank passwords (NT hash is the well-known empty-password hash)
    blank_accounts = [a for a in accounts if a["nt_hash"].lower() == BLANK_NT_HASH]

    # LM hashes present (LM field is not the disabled placeholder)
    lm_accounts = [a for a in accounts if a["lm_hash"].lower() != LM_DISABLED]

    return {
        "enabled_users": enabled_users,
        "disabled_users": disabled_users,
        "enabled_computers": enabled_computers,
        "disabled_computers": disabled_computers,
        "reused": reused,
        "reused_enabled": reused_enabled,
        "sorted_reused": sorted_reused,
        "blank_accounts": blank_accounts,
        "lm_accounts": lm_accounts,
        "total": len(accounts),
    }


# --------------------------------------------------------------------------- #
#  CSV output                                                                  #
# --------------------------------------------------------------------------- #

def write_csv(accounts: list[dict], analysis: dict, cracked: dict[str, str], out_path: str) -> None:
    # Build a lookup: nt_hash -> reuse group index (1-based, None if not reused)
    hash_to_group: dict[str, int] = {}
    for idx, (h, _) in enumerate(analysis["sorted_reused"], 1):
        hash_to_group[h] = idx

    fieldnames = [
        "domain", "username", "rid", "nt_hash",
        "account_type", "status", "password_reuse_group", "cracked_password",
        "blank_password", "lm_hash_present",
    ]
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for a in accounts:
            writer.writerow({
                "domain": a["domain"],
                "username": a["username"],
                "rid": a["rid"],
                "nt_hash": a["nt_hash"],
                "account_type": "Computer" if a["is_computer"] else "User",
                "status": a["status"],
                "password_reuse_group": hash_to_group.get(a["nt_hash"], ""),
                "cracked_password": cracked.get(a["nt_hash"].lower(), ""),
                "blank_password": "Yes" if a["nt_hash"].lower() == BLANK_NT_HASH else "",
                "lm_hash_present": "Yes" if a["lm_hash"].lower() != LM_DISABLED else "",
            })


# --------------------------------------------------------------------------- #
#  HTML output                                                                 #
# --------------------------------------------------------------------------- #

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>SecretsDump Report &mdash; {source_file}</title>
  <style>
    /* ------------------------------------------------------------------ */
    /*  Base                                                                */
    /* ------------------------------------------------------------------ */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --bg:        #0d1117;
      --bg2:       #161b22;
      --bg3:       #21262d;
      --border:    #30363d;
      --accent:    #58a6ff;
      --accent2:   #3fb950;
      --danger:    #f85149;
      --warn:      #d29922;
      --muted:     #8b949e;
      --text:      #c9d1d9;
      --text-head: #e6edf3;
      --radius:    8px;
      --font:      'Segoe UI', system-ui, -apple-system, sans-serif;
      --mono:      'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    }}

    body.light {{
      --bg:        #ffffff;
      --bg2:       #f6f8fa;
      --bg3:       #eaeef2;
      --border:    #d0d7de;
      --accent:    #0969da;
      --accent2:   #1a7f37;
      --danger:    #d1242f;
      --warn:      #9a6700;
      --muted:     #656d76;
      --text:      #1f2328;
      --text-head: #010409;
    }}

    body {{
      background: var(--bg);
      color: var(--text);
      font-family: var(--font);
      font-size: 14px;
      line-height: 1.6;
      padding: 24px;
    }}

    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}

    h1 {{ font-size: 1.6rem; color: var(--text-head); margin-bottom: 4px; }}
    h2 {{ font-size: 1.15rem; color: var(--text-head); margin: 28px 0 12px; }}
    h3 {{ font-size: 1rem; color: var(--text-head); margin-bottom: 8px; }}

    .subtitle {{
      color: var(--muted);
      font-size: 0.85rem;
      margin-bottom: 28px;
    }}

    /* ------------------------------------------------------------------ */
    /*  Summary cards                                                       */
    /* ------------------------------------------------------------------ */
    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 8px;
    }}

    .cards-findings {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(170px, 1fr));
      gap: 12px;
      margin-bottom: 32px;
    }}

    .card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 16px 20px;
    }}

    .card .label {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      margin-bottom: 6px;
      white-space: nowrap;
    }}

    .card .value {{
      font-size: 2rem;
      font-weight: 700;
      color: var(--text-head);
    }}

    .card.green .value  {{ color: var(--accent2); }}
    .card.red   .value  {{ color: var(--danger);  }}
    .card.blue  .value  {{ color: var(--accent);  }}
    .card.warn  .value  {{ color: var(--warn);    }}

    /* ------------------------------------------------------------------ */
    /*  Tables                                                              */
    /* ------------------------------------------------------------------ */
    .table-wrap {{
      overflow-x: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 24px;
    }}

    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }}

    thead th {{
      background: var(--bg3);
      color: var(--text-head);
      font-weight: 600;
      padding: 10px 14px;
      text-align: left;
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
      cursor: pointer;
      user-select: none;
    }}

    thead th:hover {{ background: var(--border); }}

    thead th.sort-asc::after  {{ content: ' ▲'; font-size: 10px; }}
    thead th.sort-desc::after {{ content: ' ▼'; font-size: 10px; }}

    tbody tr:nth-child(even) {{ background: var(--bg2); }}
    tbody tr:hover            {{ background: var(--bg3); }}

    tbody td {{
      padding: 8px 14px;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}

    tbody tr:last-child td {{ border-bottom: none; }}

    .mono {{ font-family: var(--mono); font-size: 12px; }}

    .badge {{
      display: inline-block;
      padding: 1px 8px;
      border-radius: 12px;
      font-size: 11px;
      font-weight: 600;
    }}

    .badge-enabled  {{ background: #1a3a27; color: var(--accent2); border: 1px solid #2ea043; }}
    .badge-disabled {{ background: #3a1a1a; color: var(--danger);  border: 1px solid #f85149; }}
    .badge-computer {{ background: #1a2a3a; color: var(--accent);  border: 1px solid #388bfd; }}
    .badge-user     {{ background: #2a2a1a; color: var(--warn);    border: 1px solid #d29922; }}
    .badge-cracked  {{ background: #3a3010; color: #e3b341;        border: 1px solid #d29922; }}

    body.light .badge-enabled  {{ background: #dafbe1; color: #1a7f37; border-color: #1a7f37; }}
    body.light .badge-disabled {{ background: #ffebe9; color: #d1242f; border-color: #d1242f; }}
    body.light .badge-computer {{ background: #ddf4ff; color: #0969da; border-color: #0969da; }}
    body.light .badge-user     {{ background: #fff8c5; color: #9a6700; border-color: #9a6700; }}
    body.light .badge-cracked  {{ background: #fff8c5; color: #9a6700; border-color: #9a6700; }}

    /* ------------------------------------------------------------------ */
    /*  Reuse section                                                       */
    /* ------------------------------------------------------------------ */
    .reuse-group {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 16px;
      overflow: hidden;
    }}

    .reuse-header {{
      display: flex;
      align-items: center;
      gap: 12px;
      padding: 12px 16px;
      background: var(--bg3);
      border-bottom: 1px solid var(--border);
      cursor: pointer;
    }}

    .reuse-header:hover {{ background: var(--border); }}

    .reuse-header .group-num {{
      background: var(--accent);
      color: var(--bg);
      border-radius: 50%;
      width: 24px; height: 24px;
      display: flex; align-items: center; justify-content: center;
      font-size: 11px; font-weight: 700; flex-shrink: 0;
    }}

    .reuse-header .hash {{
      font-family: var(--mono);
      font-size: 12px;
      color: #8b949e;
      background: #21262d;
      border: 1px solid var(--border);
      border-radius: 4px;
      padding: 1px 8px;
      flex-shrink: 0;
    }}

    body.light .reuse-header .hash {{
      color: #656d76;
      background: #eaeef2;
    }}

    .reuse-header .hash.copyable {{
      cursor: pointer;
      transition: border-color .15s, color .15s;
    }}

    .reuse-header .hash.copyable:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    .reuse-header .hash.copied {{
      border-color: var(--accent2);
      color: var(--accent2);
    }}

    .reuse-header .spacer {{
      flex: 1;
    }}

    .reuse-header .counts {{
      font-size: 12px;
      color: var(--text);
    }}

    .reuse-header .chevron {{
      font-size: 12px;
      color: var(--muted);
      transition: transform .2s;
    }}


    .reuse-body {{ display: none; padding: 0; }}
    .reuse-body.open {{ display: block; }}

    .reuse-header.cracked {{
      background: #2a2000;
      border-bottom-color: #6a4f00;
    }}

    .reuse-header.cracked:hover {{ background: #3a2d00; }}

    body.light .reuse-header.cracked {{
      background: #fffbe6;
      border-bottom-color: #d29922;
    }}

    body.light .reuse-header.cracked:hover {{ background: #fff3c0; }}

    .cracked-pw {{
      font-family: var(--mono);
      font-size: 12px;
      color: #e3b341;
      background: #3a3010;
      border: 1px solid #d29922;
      border-radius: 4px;
      padding: 1px 8px;
      flex-shrink: 0;
    }}

    body.light .cracked-pw {{
      color: #9a6700;
      background: #fff8c5;
      border-color: #9a6700;
    }}

    .cracked-pw.copyable {{
      cursor: pointer;
      transition: border-color .15s, color .15s;
    }}

    .cracked-pw.copyable:hover {{
      border-color: #e3b341;
      color: #fff;
    }}

    .cracked-pw.copied {{
      border-color: var(--accent2);
      color: var(--accent2);
    }}

    tr.cracked-row td {{
      background: #1e1a00 !important;
    }}

    tr.cracked-row:hover td {{
      background: #2a2500 !important;
    }}

    body.light tr.cracked-row td {{
      background: #fffbe6 !important;
    }}

    body.light tr.cracked-row:hover td {{
      background: #fff3c0 !important;
    }}

    /* ------------------------------------------------------------------ */
    /*  Section divider                                                     */
    /* ------------------------------------------------------------------ */
    .section-divider {{
      border: none;
      border-top: 1px solid var(--border);
      margin: 32px 0;
    }}

    .section-heading {{
      display: flex;
      align-items: center;
      gap: 12px;
      margin: 28px 0 12px;
    }}

    .section-heading h2 {{
      margin: 0;
    }}

    .toggle-btn {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--muted);
      cursor: pointer;
      font-size: 12px;
      padding: 3px 10px;
      transition: border-color .15s, color .15s;
    }}

    .toggle-btn:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    .toggle-btn.active {{
      background: #1a2a3a;
      border-color: var(--accent);
      color: var(--accent);
    }}

    /* ------------------------------------------------------------------ */
    /*  Pagination                                                          */
    /* ------------------------------------------------------------------ */
    .table-controls {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 6px;
      flex-wrap: wrap;
    }}

    .filter-input, .filter-select {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--text);
      font-size: 12px;
      padding: 3px 8px;
      outline: none;
    }}

    .filter-input {{ min-width: 180px; }}
    .filter-input:focus, .filter-select:focus {{ border-color: var(--accent); }}

    .pagination-bar {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-left: auto;
      font-size: 12px;
      color: var(--muted);
    }}

    .pagination-bar select {{
      background: var(--bg2);
      border: 1px solid var(--border);
      color: var(--text);
      font-size: 12px;
      padding: 2px 6px;
      border-radius: 4px;
      outline: none;
    }}

    .pagination-bar select:focus {{ border-color: var(--accent); }}

    .page-btn {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      color: var(--text);
      cursor: pointer;
      font-size: 12px;
      padding: 2px 10px;
      transition: border-color .15s, color .15s;
    }}

    .page-btn:hover:not(:disabled) {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    .page-btn:disabled {{
      opacity: 0.35;
      cursor: default;
    }}

    .page-info {{ margin: 0 4px; }}

    /* ------------------------------------------------------------------ */
    /*  Header / logo                                                       */
    /* ------------------------------------------------------------------ */
    .page-header {{
      display: flex;
      align-items: center;
      gap: 20px;
      margin-bottom: 4px;
    }}

    .page-header img {{
      height: 52px;
      width: auto;
      flex-shrink: 0;
    }}

    .page-header-right {{
      margin-left: auto;
    }}

    .theme-btn {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      color: var(--muted);
      cursor: pointer;
      font-family: var(--font);
      font-size: 12px;
      padding: 4px 10px;
      transition: border-color .15s, color .15s;
      user-select: none;
    }}

    .theme-btn:hover {{
      border-color: var(--accent);
      color: var(--accent);
    }}

    .page-header-text h1 {{
      margin-bottom: 0;
    }}

    /* ------------------------------------------------------------------ */
    /*  Footer                                                              */
    /* ------------------------------------------------------------------ */
    .page-footer {{
      margin-top: 48px;
      padding-top: 16px;
      border-top: 1px solid var(--border);
      font-size: 11px;
      color: var(--muted);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
    }}

    .page-footer a {{
      color: var(--muted);
    }}

    .page-footer a:hover {{
      color: var(--accent);
    }}

    /* ------------------------------------------------------------------ */
    /*  Tabs                                                                */
    /* ------------------------------------------------------------------ */
    .tab-bar {{
      display: flex;
      gap: 2px;
      border-bottom: 2px solid var(--border);
      margin-bottom: 24px;
      flex-wrap: wrap;
    }}

    .tab-btn {{
      background: transparent;
      border: none;
      border-bottom: 2px solid transparent;
      margin-bottom: -2px;
      color: var(--muted);
      cursor: pointer;
      font-family: var(--font);
      font-size: 13px;
      padding: 8px 16px;
      transition: color .15s, border-color .15s;
      white-space: nowrap;
    }}

    .tab-btn:hover {{ color: var(--text); }}

    .tab-btn.active {{
      color: var(--text-head);
      border-bottom-color: var(--accent);
    }}

    .tab-btn.empty {{
      color: #444d56;
      cursor: default;
    }}

    .tab-btn.empty:hover {{ color: #444d56; }}

    .tab-pane {{ display: none; }}
    .tab-pane.active {{ display: block; }}

    /* ------------------------------------------------------------------ */
    /*  Charts                                                              */
    /* ------------------------------------------------------------------ */
    .charts-row {{
      display: flex;
      gap: 24px;
      flex-wrap: wrap;
      margin-top: 24px;
    }}

    .chart-card {{
      background: var(--bg2);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 20px;
      flex: 1;
      min-width: 280px;
    }}

    .chart-card h3 {{
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: .06em;
      color: var(--muted);
      margin-bottom: 16px;
    }}

    .chart-card canvas {{
      display: block;
      margin: 0 auto;
    }}

    .chart-legend {{
      display: flex;
      flex-direction: column;
      gap: 6px;
      margin-top: 14px;
      font-size: 12px;
    }}

    .legend-item {{
      display: flex;
      align-items: center;
      gap: 8px;
    }}

    .legend-dot {{
      width: 10px; height: 10px;
      border-radius: 50%;
      flex-shrink: 0;
    }}
  </style>
</head>
<body>

<div class="page-header">
{logo_img}  <div class="page-header-text">
    <h1>SecretsDump Report</h1>
  </div>
  <div class="page-header-right">
    <button class="theme-btn" id="theme-btn" onclick="toggleTheme()">☀ Light</button>
  </div>
</div>
<p class="subtitle">
  Source: <strong>{source_file}</strong> &nbsp;&bull;&nbsp;
  Generated: <strong>{generated}</strong> &nbsp;&bull;&nbsp;
  Total entries: <strong>{total}</strong>
</p>

{tab_bar}

<!-- ======================================================= Summary -->
<div class="tab-pane active" id="pane-summary">
<div class="cards">
  <div class="card green">
    <div class="label">Enabled Users</div>
    <div class="value">{enabled_users}</div>
  </div>
  <div class="card red">
    <div class="label">Disabled Users</div>
    <div class="value">{disabled_users}</div>
  </div>
  <div class="card blue">
    <div class="label">Enabled Computers</div>
    <div class="value">{enabled_computers}</div>
  </div>
  <div class="card warn">
    <div class="label">Disabled Computers</div>
    <div class="value">{disabled_computers}</div>
  </div>
</div>
<div class="cards-findings">
  <div class="card warn">
    <div class="label">Reused Passwords</div>
    <div class="value">{reused_hash_count}</div>
  </div>
  <div class="card red">
    <div class="label">Reused PW Accounts</div>
    <div class="value">{reused_account_count}</div>
  </div>
  <div class="card red">
    <div class="label">Blank Passwords</div>
    <div class="value">{blank_count}</div>
  </div>
  <div class="card red">
    <div class="label">LM Hashes</div>
    <div class="value">{lm_count}</div>
  </div>
{cracked_card}</div>
{charts_section}
</div>

<!-- ======================================================= Password Reuse -->
<div class="tab-pane" id="pane-reuse">
{reuse_section}
</div>

<!-- ======================================================= Cracked Passwords -->
<div class="tab-pane" id="pane-cracked">
{cracked_section}
</div>

<!-- ======================================================= Blank Passwords -->
<div class="tab-pane" id="pane-blank">
{blank_section}
</div>

<!-- ======================================================= LM Hashes -->
<div class="tab-pane" id="pane-lm">
{lm_section}
</div>

<script>
// ---------------------------------------------------------- theme toggle
function toggleTheme() {{
  const light = document.body.classList.toggle('light');
  document.getElementById('theme-btn').textContent = light ? '☽ Dark' : '☀ Light';
  localStorage.setItem('sdr-theme', light ? 'light' : 'dark');
  if (typeof _drawCharts === 'function') _drawCharts();
}}

(function() {{
  if (localStorage.getItem('sdr-theme') === 'light') {{
    document.body.classList.add('light');
    document.addEventListener('DOMContentLoaded', () => {{
      const btn = document.getElementById('theme-btn');
      if (btn) btn.textContent = '☽ Dark';
    }});
  }}
}})();

// ---------------------------------------------------------- tabs
function switchTab(id) {{
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const pane = document.getElementById('pane-' + id);
  const btn  = document.getElementById('tab-' + id);
  if (pane) pane.classList.add('active');
  if (btn)  btn.classList.add('active');
  history.replaceState(null, '', '#' + id);
  ['cracked-table', 'blank-table', 'lm-table'].forEach(tid => {{
    const t = document.getElementById(tid);
    if (t && t.closest('.tab-pane') === pane && !_pageState[tid]) paginate(tid);
  }});
}}

window.addEventListener('hashchange', () => {{
  const id = location.hash.replace('#', '') || 'summary';
  const btn = document.getElementById('tab-' + id);
  if (btn && !btn.classList.contains('empty')) switchTab(id);
}});

// ---------------------------------------------------------- collapsibles
function toggleReuse(el) {{
  const body    = el.nextElementSibling;
  const chevron = el.querySelector('.chevron');
  const open    = body.classList.toggle('open');
  chevron.style.transform = open ? 'rotate(90deg)' : '';
}}

// ---------------------------------------------------------- charts
function drawPie(canvasId, data) {{
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const cx = canvas.width / 2, cy = canvas.height / 2;
  const r  = Math.min(cx, cy) - 8;
  const total = data.reduce((s, d) => s + d.value, 0);
  if (total === 0) return;
  let angle = -Math.PI / 2;
  data.forEach(d => {{
    const slice = (d.value / total) * 2 * Math.PI;
    ctx.beginPath();
    ctx.moveTo(cx, cy);
    ctx.arc(cx, cy, r, angle, angle + slice);
    ctx.closePath();
    ctx.fillStyle = d.color;
    ctx.fill();
    angle += slice;
  }});
}}

function drawBar(canvasId, data) {{
  const canvas = document.getElementById(canvasId);
  if (!canvas || !data.length) return;
  const ctx   = canvas.getContext('2d');
  const W = canvas.width, H = canvas.height;
  const padL = 44, padR = 12, padT = 16, padB = 28;
  const chartW = W - padL - padR;
  const chartH = H - padT - padB;
  const maxVal = Math.max(...data.map(d => d.value));
  const yMax   = Math.max(maxVal, 3); // minimum y range of 3 to avoid cramped labels
  const barW   = Math.max(4, Math.floor(chartW / data.length) - 3);

  ctx.clearRect(0, 0, W, H);

  // integer ticks — show at most 5, always include 0 and yMax
  const tickCount = Math.min(yMax, 5);
  const tickVals  = new Set([0]);
  for (let i = 1; i <= tickCount; i++) tickVals.add(Math.round(yMax * i / tickCount));

  tickVals.forEach(v => {{
    const y = padT + chartH * (1 - v / yMax);
    ctx.strokeStyle = '#30363d';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(padL, y); ctx.lineTo(W - padR, y); ctx.stroke();
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px monospace';
    ctx.textAlign = 'right';
    ctx.fillText(v, padL - 6, y + 3);
  }});

  // bars
  data.forEach((d, i) => {{
    const x  = padL + i * (chartW / data.length);
    const bh = (d.value / yMax) * chartH;
    const y  = padT + chartH - bh;
    ctx.fillStyle = '#58a6ff';
    ctx.fillRect(x + 1, y, barW, bh);
    ctx.fillStyle = '#8b949e';
    ctx.font = '10px monospace';
    ctx.textAlign = 'center';
    ctx.fillText(d.label, x + barW / 2 + 1, H - padB + 14);
  }});
}}

// ---------------------------------------------------------- copy hash
function copyHash(event, el, text) {{
  event.stopPropagation();
  const original = el.textContent;
  navigator.clipboard.writeText(text).then(() => {{
    el.textContent = 'copied!';
    el.classList.add('copied');
    setTimeout(() => {{
      el.textContent = original;
      el.classList.remove('copied');
    }}, 1500);
  }});
}}
// ---------------------------------------------------------- toggle disabled
function toggleDisabled(tableId, btnId) {{
  const btn  = document.getElementById(btnId);
  const hide = btn.classList.toggle('active');
  btn.textContent = hide ? 'Show Disabled' : 'Hide Disabled';
  document.querySelectorAll('#' + tableId + ' tbody tr[data-disabled="1"]').forEach(r => {{
    r._hiddenByToggle = hide;
  }});
  applyVisibility(tableId);
  paginate(tableId);
}}

// ---------------------------------------------------------- filtering
function filterTable(tableId) {{
  const search    = (document.getElementById(tableId + '-search')  || {{}}).value || '';
  const typeVal   = (document.getElementById(tableId + '-type')    || {{}}).value || '';
  const domainVal = (document.getElementById(tableId + '-domain')  || {{}}).value || '';
  const needle    = search.trim().toLowerCase();
  const table     = document.getElementById(tableId);
  const searchCols = table ? (table.dataset.searchCols || '').split(',').map(Number) : [];
  const tbody     = document.querySelector('#' + tableId + ' tbody');
  Array.from(tbody.rows).forEach(r => {{
    const domainCell = r.querySelector('td:nth-child(1)');
    const typeCell   = r.querySelector('td:nth-child(3)');
    const matchText  = !needle || searchCols.some(c => {{
      const cell = r.cells[c];
      return cell && cell.textContent.toLowerCase().includes(needle);
    }});
    const matchType   = !typeVal   || (typeCell   && typeCell.textContent.trim().toUpperCase()   === typeVal.toUpperCase());
    const matchDomain = !domainVal || (domainCell && domainCell.textContent.trim() === domainVal);
    r._hiddenByFilter = !(matchText && matchType && matchDomain);
  }});
  applyVisibility(tableId);
  _pageState[tableId] = {{ page: 1 }};
  paginate(tableId);
}}

function applyVisibility(tableId) {{
  const tbody = document.querySelector('#' + tableId + ' tbody');
  Array.from(tbody.rows).forEach(r => {{
    r.style.display = (r._hiddenByToggle || r._hiddenByFilter) ? 'none' : '';
  }});
}}

// ---------------------------------------------------------- pagination
const _pageState = {{}};

function paginate(tableId) {{
  const state   = _pageState[tableId] || (_pageState[tableId] = {{ page: 1 }});
  const sizeEl  = document.getElementById(tableId + '-size');
  const pageSize = sizeEl ? (sizeEl.value === 'all' ? Infinity : parseInt(sizeEl.value)) : 25;
  const tbody   = document.querySelector('#' + tableId + ' tbody');
  const rows    = Array.from(tbody.rows).filter(r => !r._hiddenByToggle && !r._hiddenByFilter);
  const total   = rows.length;
  const pages   = pageSize === Infinity ? 1 : Math.max(1, Math.ceil(total / pageSize));

  if (state.page > pages) state.page = pages;

  // hide all first, then show only current page
  Array.from(tbody.rows).forEach(r => {{
    if (!r._hiddenByToggle && !r._hiddenByFilter) r.style.display = 'none';
  }});
  rows.forEach((r, i) => {{
    const inPage = pageSize === Infinity || (i >= (state.page - 1) * pageSize && i < state.page * pageSize);
    if (inPage) r.style.display = '';
  }});

  // Update controls
  const info   = document.getElementById(tableId + '-info');
  const prev   = document.getElementById(tableId + '-prev');
  const next   = document.getElementById(tableId + '-next');
  if (info) {{
    if (pageSize === Infinity || pages === 1) {{
      info.textContent = total + ' rows';
    }} else {{
      const from = Math.min((state.page - 1) * pageSize + 1, total);
      const to   = Math.min(state.page * pageSize, total);
      info.textContent = from + '–' + to + ' of ' + total;
    }}
  }}
  if (prev) prev.disabled = state.page <= 1;
  if (next) next.disabled = state.page >= pages;
}}

function changePage(tableId, delta) {{
  const state = _pageState[tableId] || (_pageState[tableId] = {{ page: 1 }});
  state.page += delta;
  paginate(tableId);
}}

function changePageSize(tableId) {{
  _pageState[tableId] = {{ page: 1 }};
  paginate(tableId);
}}

document.addEventListener('DOMContentLoaded', () => {{
  const id = location.hash.replace('#', '') || 'summary';
  const btn = document.getElementById('tab-' + id);
  if (btn && !btn.classList.contains('empty')) {{
    switchTab(id);
  }} else {{
    switchTab('summary');
  }}
  // draw charts after tab is visible
  if (typeof _drawCharts === 'function') _drawCharts();
}});
</script>
<footer class="page-footer">
  <span style="display:flex; align-items:center; gap:8px;">
    <a href="https://github.com/yepskotch/SecretsDumpReporter" target="_blank" title="github.com/yepskotch/SecretsDumpReporter">
      <svg height="16" width="16" viewBox="0 0 16 16" fill="currentColor" xmlns="http://www.w3.org/2000/svg">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
                 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13
                 -.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66
                 .07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15
                 -.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27
                 .68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12
                 .51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48
                 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
      </svg>
    </a>
    <span>SecretsDump Reporter v{version}</span>
  </span>
</footer>
</body>
</html>
"""


def badge(text: str, cls: str) -> str:
    return f'<span class="badge badge-{cls}">{text}</span>'


def pagination_bar(table_id: str, toggle_id: str, domains: list[str]) -> str:
    domain_opts = '<option value="">All domains</option>\n' + "\n".join(
        f'    <option value="{d}">{d if d else "(no domain)"}</option>'
        for d in sorted(domains)
    )
    return f"""\
<div class="table-controls">
  <input class="filter-input" id="{table_id}-search" type="text" placeholder="Search username, hash&#8230;" oninput="filterTable('{table_id}')">
  <select class="filter-select" id="{table_id}-domain" onchange="filterTable('{table_id}')">
    {domain_opts}
  </select>
  <select class="filter-select" id="{table_id}-type" onchange="filterTable('{table_id}')">
    <option value="">All types</option>
    <option value="USER">User</option>
    <option value="COMPUTER">Computer</option>
  </select>
  <button class="toggle-btn" id="{toggle_id}" onclick="toggleDisabled('{table_id}', '{toggle_id}')">Hide Disabled</button>
  <div class="pagination-bar">
    <span>Show</span>
    <select id="{table_id}-size" onchange="changePageSize('{table_id}')">
      <option value="25">25</option>
      <option value="50">50</option>
      <option value="100">100</option>
      <option value="all">All</option>
    </select>
    <span>rows</span>
    <button class="page-btn" id="{table_id}-prev" onclick="changePage('{table_id}', -1)">&#8592;</button>
    <span class="page-info" id="{table_id}-info"></span>
    <button class="page-btn" id="{table_id}-next" onclick="changePage('{table_id}', 1)">&#8594;</button>
  </div>
</div>"""


def redact_hash(h: str) -> str:
    return h[:4] + "*" * (len(h) - 8) + h[-4:]


def build_reuse_section(analysis: dict, cracked: dict[str, str], redacted: bool = False) -> str:
    if not analysis["sorted_reused"]:
        return "<p>No password reuse detected.</p>"

    parts = []
    for idx, (nt_hash, all_accs) in enumerate(analysis["sorted_reused"], 1):
        enabled_accs = analysis["reused_enabled"].get(nt_hash, [])
        total_count = len(all_accs)
        enabled_count = len(enabled_accs)
        password = cracked.get(nt_hash.lower())
        if redacted:
            hash_span = f'<span class="hash">{redact_hash(nt_hash)}</span>'
        else:
            hash_span = f'<span class="hash copyable" title="Click to copy" onclick="copyHash(event, this, \'{nt_hash}\')">{nt_hash}</span>'

        if password and redacted:
            cracked_indicator = '<span class="cracked-pw">CRACKED</span>\n    '
        elif password:
            cracked_indicator = f'<span class="cracked-pw copyable" title="Click to copy" onclick="copyHash(event, this, \'{password}\')">{password}</span>\n    '
        else:
            cracked_indicator = ""

        header_class = ' cracked' if password else ''

        parts.append(f"""
<div class="reuse-group">
  <div class="reuse-header{header_class}" onclick="toggleReuse(this)">
    <span class="group-num">{idx}</span>
    {hash_span}
    {cracked_indicator}<span class="spacer"></span><span class="counts">
      {total_count} total &nbsp;|&nbsp; {enabled_count} enabled
    </span>
    <span class="chevron">&#9658;</span>
  </div>
  <div class="reuse-body">
    <div class="table-wrap" style="border:none; border-radius:0; margin:0;">
      <table>
        <thead>
          <tr>
            <th>Domain</th>
            <th>Username</th>
            <th>Type</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
""")
        for a in sorted(all_accs, key=lambda x: (not x["enabled"], x["username"])):
            status_badge = badge(a["status"], "enabled" if a["enabled"] else "disabled")
            type_badge = badge("Computer" if a["is_computer"] else "User",
                               "computer" if a["is_computer"] else "user")
            parts.append(f"""\
          <tr>
            <td>{a['domain']}</td>
            <td>{a['username']}</td>
            <td>{type_badge}</td>
            <td>{status_badge}</td>
          </tr>
""")
        parts.append("""\
        </tbody>
      </table>
    </div>
  </div>
</div>
""")
    return "".join(parts)


def build_cracked_section(accounts: list[dict], cracked: dict[str, str], redacted: bool = False) -> str:
    """Build the 'Cracked Passwords' section listing all accounts with a cracked hash."""
    cracked_accounts = [
        a for a in accounts
        if a["nt_hash"].lower() in cracked and a["nt_hash"].lower() != BLANK_NT_HASH
    ]
    if not cracked_accounts:
        return ""

    rows = []
    for a in sorted(cracked_accounts, key=lambda x: (not x["enabled"], x["username"])):
        status_badge = badge(a["status"], "enabled" if a["enabled"] else "disabled")
        type_badge = badge("Computer" if a["is_computer"] else "User",
                           "computer" if a["is_computer"] else "user")
        password = cracked[a["nt_hash"].lower()]
        if redacted:
            hash_cell = f'<span class="mono">{redact_hash(a["nt_hash"])}</span>'
            pw_cell = badge("CRACKED", "cracked")
        else:
            hash_cell = f'<span class="mono cracked-pw copyable" title="Click to copy" onclick="copyHash(event, this, \'{a["nt_hash"]}\')">{a["nt_hash"]}</span>'
            pw_cell = f'<span class="mono cracked-pw copyable" title="Click to copy" onclick="copyHash(event, this, \'{password}\')">{password}</span>'
        rows.append(f"""\
      <tr class="cracked-row" data-disabled="{'1' if not a['enabled'] else '0'}">
        <td>{a['domain']}</td>
        <td>{a['username']}</td>
        <td>{type_badge}</td>
        <td>{status_badge}</td>
        <td>{hash_cell}</td>
        <td>{pw_cell}</td>
      </tr>
""")

    pw_header = "Password" if not redacted else "Status"
    domains = sorted({a["domain"] for a in cracked_accounts})
    # search cols: 1=username, 4=NT hash, 5=password
    return f"""\
{pagination_bar('cracked-table', 'cracked-toggle', domains)}
<div class="table-wrap">
  <table id="cracked-table" data-search-cols="1,4,5">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Username</th>
        <th>Type</th>
        <th>Status</th>
        <th>NT Hash</th>
        <th>{pw_header}</th>
      </tr>
    </thead>
    <tbody>
{"".join(rows)}    </tbody>
  </table>
</div>
"""


def build_blank_section(analysis: dict) -> str:
    """Build the 'Blank Passwords' section — same content for full and redacted reports."""
    accounts = analysis["blank_accounts"]
    if not accounts:
        return ""

    rows = []
    for a in sorted(accounts, key=lambda x: (not x["enabled"], x["username"])):
        status_badge = badge(a["status"], "enabled" if a["enabled"] else "disabled")
        type_badge   = badge("Computer" if a["is_computer"] else "User",
                             "computer" if a["is_computer"] else "user")
        rows.append(f"""\
      <tr data-disabled="{'1' if not a['enabled'] else '0'}">
        <td>{a['domain']}</td>
        <td>{a['username']}</td>
        <td>{type_badge}</td>
        <td>{status_badge}</td>
      </tr>
""")

    domains = sorted({a["domain"] for a in accounts})
    # search cols: 1=username
    return f"""\
{pagination_bar('blank-table', 'blank-toggle', domains)}
<div class="table-wrap">
  <table id="blank-table" data-search-cols="1">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Username</th>
        <th>Type</th>
        <th>Status</th>
      </tr>
    </thead>
    <tbody>
{"".join(rows)}    </tbody>
  </table>
</div>
"""


def build_lm_section(analysis: dict, redacted: bool = False) -> str:
    """Build the 'LM Hashes' section."""
    accounts = analysis["lm_accounts"]
    if not accounts:
        return ""

    rows = []
    for a in sorted(accounts, key=lambda x: (not x["enabled"], x["username"])):
        status_badge = badge(a["status"], "enabled" if a["enabled"] else "disabled")
        type_badge   = badge("Computer" if a["is_computer"] else "User",
                             "computer" if a["is_computer"] else "user")
        if redacted:
            lm_cell = f'<span class="mono">{redact_hash(a["lm_hash"])}</span>'
        else:
            lm_cell = f'<span class="mono cracked-pw copyable" title="Click to copy" onclick="copyHash(event, this, \'{a["lm_hash"]}\')">{a["lm_hash"]}</span>'
        rows.append(f"""\
      <tr data-disabled="{'1' if not a['enabled'] else '0'}">
        <td>{a['domain']}</td>
        <td>{a['username']}</td>
        <td>{type_badge}</td>
        <td>{status_badge}</td>
        <td>{lm_cell}</td>
      </tr>
""")

    lm_header = "LM Hash" if not redacted else "LM Hash (Redacted)"
    domains = sorted({a["domain"] for a in accounts})
    # search cols: 1=username, 4=LM hash
    return f"""\
<p style="font-size:12px; color: var(--muted); margin-bottom: 12px;">
  These accounts have LM hashing enabled. LM hashes are trivially crackable (max 14 chars, case-insensitive, split into two 7-char halves).
</p>
{pagination_bar('lm-table', 'lm-toggle', domains)}
<div class="table-wrap">
  <table id="lm-table" data-search-cols="1,4">
    <thead>
      <tr>
        <th>Domain</th>
        <th>Username</th>
        <th>Type</th>
        <th>Status</th>
        <th>{lm_header}</th>
      </tr>
    </thead>
    <tbody>
{"".join(rows)}    </tbody>
  </table>
</div>
"""


def build_charts_section(accounts: list[dict], cracked: dict[str, str]) -> str:
    """Build pie + bar charts for the summary tab. Returns empty string if no potfile."""
    if not cracked:
        return ""

    # Unique NT hashes, excluding blank password
    all_unique = {a["nt_hash"].lower() for a in accounts
                  if a["nt_hash"].lower() != BLANK_NT_HASH and not a["is_computer"]}
    cracked_unique = {h for h in all_unique if h in cracked}
    uncracked_unique = all_unique - cracked_unique

    num_cracked   = len(cracked_unique)
    num_uncracked = len(uncracked_unique)

    total_unique = num_cracked + num_uncracked
    cracked_pct   = round(num_cracked   / total_unique * 100, 1) if total_unique else 0
    uncracked_pct = round(num_uncracked / total_unique * 100, 1) if total_unique else 0

    pie_data = [
        {"value": num_cracked,   "color": "#d29922", "label": f"Cracked ({num_cracked} — {cracked_pct}%)"},
        {"value": num_uncracked, "color": "#30363d", "label": f"Uncracked ({num_uncracked} — {uncracked_pct}%)"},
    ]    # Password length distribution (unique cracked passwords only)
    length_counts: dict[int, int] = {}
    for h in cracked_unique:
        pw = cracked[h]
        length_counts[len(pw)] = length_counts.get(len(pw), 0) + 1

    bar_data = [{"label": str(l), "value": c}
                for l, c in sorted(length_counts.items())]

    import json
    pie_json = json.dumps(pie_data)
    bar_json = json.dumps(bar_data)

    legend_html = "\n".join(
        f'<div class="legend-item"><div class="legend-dot" style="background:{d["color"]}"></div><span>{d["label"]}</span></div>'
        for d in pie_data
    )

    return f"""\
<div class="charts-row">
  <div class="chart-card">
    <h3>User Password Coverage</h3>
    <canvas id="pie-chart" width="180" height="180"></canvas>
    <div class="chart-legend">{legend_html}</div>
  </div>
  <div class="chart-card" style="flex:2; min-width:360px;">
    <h3>Cracked Password Lengths</h3>
    <canvas id="bar-chart" width="560" height="200"></canvas>
  </div>
</div>
<script>
function _drawCharts() {{
  const light = document.body.classList.contains('light');
  const pieData = {pie_json};
  // adjust uncracked slice colour for light mode
  if (pieData[1]) pieData[1].color = light ? '#d0d7de' : '#30363d';
  const barData = {bar_json};
  drawPie('pie-chart', pieData);
  drawBar('bar-chart', barData);
}}
</script>"""


def build_tab_bar(analysis: dict, reuse_cracked_count: int, cracked_account_count: int, has_cracked_potfile: bool) -> str:
    reuse_label = "Password Reuse"
    if reuse_cracked_count:
        reuse_label += f' <span style="font-size:0.8em;color:var(--warn);">({reuse_cracked_count} Cracked)</span>'

    tabs = [
        ("summary", "Summary",          True),
        ("reuse",   reuse_label,         bool(analysis["sorted_reused"])),
    ]
    if has_cracked_potfile:
        tabs.append(("cracked", "Cracked Passwords", bool(cracked_account_count)))
    tabs += [
        ("blank", "Blank Passwords", bool(analysis["blank_accounts"])),
        ("lm",    "LM Hashes",       bool(analysis["lm_accounts"])),
    ]

    buttons = []
    for tab_id, label, has_content in tabs:
        cls = "tab-btn" + ("" if has_content else " empty")
        onclick = f'onclick="switchTab(\'{tab_id}\')"' if has_content else ""
        buttons.append(f'  <button class="{cls}" id="tab-{tab_id}" {onclick}>{label}</button>')

    return '<div class="tab-bar">\n' + '\n'.join(buttons) + '\n</div>'


def write_html(accounts: list[dict], analysis: dict, cracked: dict[str, str], source_file: str, out_path: str, redacted: bool = False) -> None:
    reused_account_count = sum(len(v) for v in analysis["reused"].values())
    cracked_account_count = sum(
        1 for a in accounts
        if a["nt_hash"].lower() in cracked and a["nt_hash"].lower() != BLANK_NT_HASH
    )

    # Number of reused hashes that have been cracked
    cracked_reuse_count = sum(
        1 for h, _ in analysis["sorted_reused"] if h.lower() in cracked
    )

    if cracked:
        cracked_card = (
            '  <div class="card red">\n'
            '    <div class="label">Cracked Accounts</div>\n'
            f'    <div class="value">{cracked_account_count}</div>\n'
            '  </div>\n'
        )
    else:
        cracked_card = ""

    logo_img = f'  <img src="{_LOGO_DATA_URI}" alt="Logo" />\n'

    tab_bar = build_tab_bar(
        analysis,
        reuse_cracked_count=cracked_reuse_count,
        cracked_account_count=cracked_account_count,
        has_cracked_potfile=bool(cracked),
    )

    html = HTML_TEMPLATE.format(
        source_file=Path(source_file).name,
        generated=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=analysis["total"],
        enabled_users=len(analysis["enabled_users"]),
        disabled_users=len(analysis["disabled_users"]),
        enabled_computers=len(analysis["enabled_computers"]),
        disabled_computers=len(analysis["disabled_computers"]),
        reused_hash_count=len(analysis["reused"]),
        reused_account_count=reused_account_count,
        cracked_card=cracked_card,
        tab_bar=tab_bar,
        charts_section=build_charts_section(accounts, cracked),
        reuse_section=build_reuse_section(analysis, cracked, redacted=redacted),
        cracked_section=build_cracked_section(accounts, cracked, redacted=redacted),
        blank_section=build_blank_section(analysis),
        lm_section=build_lm_section(analysis, redacted=redacted),
        blank_count=len(analysis["blank_accounts"]),
        lm_count=len(analysis["lm_accounts"]),
        logo_img=logo_img,
        version=_VERSION,
    )

    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(html)


# --------------------------------------------------------------------------- #
#  Entry point                                                                 #
# --------------------------------------------------------------------------- #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyse secretsdump output and produce an HTML report + CSV."
    )
    parser.add_argument("input", help="Path to the secretsdump output file")
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Base name for output files (default: input filename without extension)"
    )
    parser.add_argument(
        "-p", "--potfile",
        default=None,
        help="Path to a hashcat .potfile to match cracked passwords"
    )
    args = parser.parse_args()

    input_path = args.input
    base = args.output or Path(input_path).stem

    html_path           = base + ".html"
    html_redacted_path  = base + "_redacted.html"
    csv_path            = base + ".csv"

    print(f"[*] Parsing {input_path}...")
    accounts = parse_file(input_path)

    if not accounts:
        print("[!] No accounts parsed. Check that the file contains secretsdump output with -user-status.", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Parsed {len(accounts)} accounts.")

    cracked: dict[str, str] = {}
    if args.potfile:
        cracked = parse_potfile(args.potfile)
        matched = sum(1 for a in accounts if a["nt_hash"].lower() in cracked)
        print(f"[*] Potfile loaded: {len(cracked)} hashes, {matched} accounts matched.")

    analysis = analyse(accounts)

    print(f"[*] Writing HTML report            -> {html_path}")
    write_html(accounts, analysis, cracked, input_path, html_path)

    print(f"[*] Writing HTML report (redacted) -> {html_redacted_path}")
    write_html(accounts, analysis, cracked, input_path, html_redacted_path, redacted=True)

    print(f"[*] Writing CSV                    -> {csv_path}")
    write_csv(accounts, analysis, cracked, csv_path)

    # Quick summary to stdout
    print()
    print("  Summary")
    print(f"  {'Enabled users:':<28} {len(analysis['enabled_users'])}")
    print(f"  {'Disabled users:':<28} {len(analysis['disabled_users'])}")
    print(f"  {'Enabled computers:':<28} {len(analysis['enabled_computers'])}")
    print(f"  {'Disabled computers:':<28} {len(analysis['disabled_computers'])}")
    print(f"  {'Reused NT hashes:':<28} {len(analysis['reused'])}")
    reused_acct = sum(len(v) for v in analysis['reused'].values())
    print(f"  {'Accounts w/ reused pw:':<28} {reused_acct}")
    if cracked:
        matched = sum(
            1 for a in accounts
            if a["nt_hash"].lower() in cracked and a["nt_hash"].lower() != BLANK_NT_HASH
        )
        print(f"  {'Cracked accounts:':<28} {matched}")
    print(f"  {'Blank passwords:':<28} {len(analysis['blank_accounts'])}")
    print(f"  {'LM hashes present:':<28} {len(analysis['lm_accounts'])}")
    print()


if __name__ == "__main__":
    main()
