"""CIPHER-X | Security Operations Center dashboard.

Read-only Streamlit console for the CIPHER-X endpoint agent.

Every figure rendered here is derived from data/events.jsonl. Nothing is
hardcoded, sampled or simulated: when the log is empty the panels say so.
The file is opened read-only and is never written to or truncated.

Layout
    Data layer      load / normalize / index the event log
    Metric layer    counts, severity rollups, time buckets
    Render layer    self-contained HTML blocks + native Streamlit widgets
    Views           overview, alerts, detections, processes, files, cases
"""

from __future__ import annotations

import json
import os
from collections import Counter, OrderedDict, namedtuple
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path

import streamlit as st

# --------------------------------------------------------------------------
# Paths and constants
# --------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_EVENTS_FILE = BASE_DIR / "data" / "events.jsonl"

APP_NAME = "CIPHER-X"
APP_ROLE = "Security Operations Center"
APP_TAGLINE = "Windows endpoint telemetry, detection, correlation, and response monitoring"
APP_VERSION = "v1.0"

EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)
DASH = "\u2014"

Page = namedtuple("Page", "name icon handler")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "info", "unknown")

SEVERITY_COLORS = {
    "critical": "#ff4d6d",
    "high": "#ff9f45",
    "medium": "#ffd166",
    "low": "#38bdf8",
    "info": "#5eb0ef",
    "unknown": "#5c7b96",
}

SEVERITY_ALIASES = {
    "crit": "critical",
    "critical": "critical",
    "severe": "critical",
    "sev1": "critical",
    "high": "high",
    "sev2": "high",
    "important": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "sev3": "medium",
    "low": "low",
    "sev4": "low",
    "minor": "low",
    "info": "info",
    "informational": "info",
    "information": "info",
    "notice": "info",
}

RESOLVED_STATUSES = {
    "closed",
    "resolved",
    "dismissed",
    "suppressed",
    "false_positive",
    "false positive",
    "benign",
    "remediated",
    "mitigated",
}

PROCESS_TYPES = {"process_observed", "process_event", "process_created", "process_start"}
DETECTION_TYPES = {"security_detection", "detection"}
# Event types whose detections count as rule hits (see get_metrics). Add
# "file_security_detection" here to fold file detections into the same stats.
RULE_HIT_TYPES = DETECTION_TYPES
ALERT_TYPES = {"security_alert", "alert"}
CORRELATION_TYPES = {"correlation_alert", "correlation"}
FILE_TYPES = {
    "file_integrity_event",
    "file_security_detection",
    "file_event",
    "file_modified",
    "file_created",
}

ACCENT = "#38bdf8"
ACCENT_SOFT = "#22d3ee"

# --- Display limits -------------------------------------------------------
# Tune the console here; the render functions read these, never literals.
RECENT_EVENTS_LIMIT = 12
ALERT_QUEUE_LIMIT = 25
DETECTION_TABLE_LIMIT = 200
FILE_TABLE_LIMIT = 200
CASE_LIMIT = 12
RELATED_EVENTS_LIMIT = 20
TOP_RULES_LIMIT = 5
TOP_MITRE_LIMIT = 8
TOP_PROCESSES_LIMIT = 10
EVENT_TYPE_LIMIT = 10
PROCESS_ROWS_MIN = 25
PROCESS_ROWS_MAX = 500
PROCESS_ROWS_DEFAULT = 100
PROCESS_ROWS_STEP = 25
MAX_CHART_BUCKETS = 34
CHART_POINT_MARKER_LIMIT = 30

# Risk meters are drawn against this ceiling. CIPHER-X scores risk 0-100.
RISK_SCORE_CEILING = 100.0

# How far either side of an alert to look for telemetry on the same PID
# or process when building the investigation view.
CORRELATION_WINDOW_SECONDS = 120

# --------------------------------------------------------------------------
# Page config (must run before any other Streamlit call)
# --------------------------------------------------------------------------

st.set_page_config(
    page_title=f"{APP_NAME} | {APP_ROLE}",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700;800&family=Inter:wght@400;500;600;700&display=swap');

:root{
  --cx-panel-2:#0a192f;
  --cx-line:rgba(56,189,248,0.18);
  --cx-line-strong:rgba(56,189,248,0.48);
  --cx-accent:#38bdf8;
  --cx-accent-2:#22d3ee;
  --cx-text:#e6f1ff;
  --cx-muted:#7c9bb8;
  --cx-dim:#54748f;
}

html, body, .stApp, [data-testid="stAppViewContainer"]{
  font-family:'Inter',-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
}

.stApp{
  background:
    radial-gradient(1100px 520px at 50% -12%, rgba(13,86,150,0.42) 0%, rgba(2,8,23,0) 62%),
    linear-gradient(180deg,#020817 0%,#01060f 100%);
  color:var(--cx-text);
}

[data-testid="stAppViewContainer"]::before{
  content:"";
  position:fixed;
  inset:0;
  pointer-events:none;
  z-index:0;
  background-image:
    linear-gradient(rgba(56,189,248,0.05) 1px, transparent 1px),
    linear-gradient(90deg, rgba(56,189,248,0.05) 1px, transparent 1px);
  background-size:54px 54px;
  -webkit-mask-image:radial-gradient(circle at 50% -5%, #000 0%, transparent 72%);
  mask-image:radial-gradient(circle at 50% -5%, #000 0%, transparent 72%);
}

/* Hide Streamlit's own menu/deploy/status chrome, but leave the toolbar
   container itself alone: it's also where Streamlit renders its native
   "reopen sidebar" chevron when the sidebar is collapsed, and hiding the
   whole container hid that control along with the clutter. */
#MainMenu, footer, [data-testid="stAppDeployButton"], [data-testid="stToolbarActions"],
[data-testid="stDecoration"], [data-testid="stStatusWidget"]{
  display:none !important;
}
[data-testid="stHeader"]{background:transparent;}

/* Streamlit's native sidebar-reopen control. It only exists in the DOM
   while the sidebar is collapsed, so this never appears while it's open
   and needs no visibility logic of our own. Restyled as a fixed CIPHER-X
   pill so it stays reachable above any page content. */
[data-testid="stExpandSidebarButton"]{
  position:fixed !important;
  top:14px !important;
  left:14px !important;
  z-index:999999 !important;
  display:flex !important;
  align-items:center;
  justify-content:center;
  width:38px !important;
  height:38px !important;
  padding:0 !important;
  margin:0 !important;
  background:rgba(10,25,47,0.92) !important;
  border:1px solid var(--cx-accent) !important;
  border-radius:9px !important;
  box-shadow:0 0 16px rgba(56,189,248,0.42) !important;
  opacity:1 !important;
  visibility:visible !important;
  transition:box-shadow .15s, background .15s, border-color .15s;
}
[data-testid="stExpandSidebarButton"]:hover{
  background:rgba(14,52,88,0.95) !important;
  border-color:#6fdcff !important;
  box-shadow:0 0 22px rgba(56,189,248,0.65) !important;
}
[data-testid="stExpandSidebarButton"]:focus-visible{
  outline:2px solid var(--cx-accent) !important;
  outline-offset:2px;
}
[data-testid="stExpandSidebarButton"] svg,
[data-testid="stExpandSidebarButton"] svg *,
[data-testid="stExpandSidebarButton"] span,
[data-testid="stExpandSidebarButton"] i{
  color:var(--cx-accent) !important;
  fill:currentColor !important;
  opacity:1 !important;
}

.block-container{
  max-width:1680px;
  padding:10px 30px 46px 30px;
  position:relative;
  z-index:1;
}

/* ---------------- sidebar ---------------- */
[data-testid="stSidebar"]{
  background:linear-gradient(180deg,#04101f 0%,#020813 100%);
  border-right:1px solid var(--cx-line);
  box-shadow:14px 0 40px rgba(0,0,0,0.5);
}
[data-testid="stSidebar"] [data-testid="stSidebarUserContent"]{padding-top:8px;}
[data-testid="stSidebar"] hr{border-color:var(--cx-line);}

.cx-side-brand{display:flex;align-items:center;gap:11px;padding:6px 2px 14px 2px;}
.cx-side-brand .cx-mark{width:34px;height:34px;flex:none;}
.cx-side-name{font-family:'Orbitron',sans-serif;font-size:19px;font-weight:800;letter-spacing:2px;color:#f2f9ff;line-height:1;}
.cx-side-name em{color:var(--cx-accent);font-style:normal;}
.cx-side-role{font-size:8.5px;letter-spacing:0.18em;color:var(--cx-muted);margin-top:5px;}

.cx-side-status{
  display:flex;align-items:center;gap:9px;
  border:1px solid var(--cx-line);border-radius:9px;
  background:rgba(10,25,47,0.75);
  padding:9px 12px;margin-bottom:14px;
}
.cx-dot{width:8px;height:8px;border-radius:50%;background:var(--cx-accent);box-shadow:0 0 10px var(--cx-accent);}
.cx-side-status .t{font-size:11px;letter-spacing:0.16em;color:#cfe9ff;font-weight:600;}
.cx-side-status .s{font-size:9.5px;color:var(--cx-dim);letter-spacing:0.1em;margin-left:auto;}

.cx-side-label{font-size:9px;letter-spacing:0.2em;color:var(--cx-dim);margin:4px 2px 8px 2px;}
.cx-side-metrics{border:1px solid var(--cx-line);border-radius:10px;background:rgba(7,20,38,0.7);overflow:hidden;margin-bottom:6px;}
.cx-side-metric{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid rgba(56,189,248,0.09);}
.cx-side-metric:last-child{border-bottom:none;}
.cx-side-metric .k{font-size:10.5px;color:var(--cx-muted);letter-spacing:0.06em;}
.cx-side-metric .v{font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700;color:#eaf6ff;}
.cx-side-foot{font-size:9.5px;letter-spacing:0.16em;color:var(--cx-dim);text-align:center;padding-top:6px;}

/* ---------------- buttons ---------------- */
.stButton>button{
  width:100%;
  background:rgba(10,25,47,0.85);
  color:#bfe4ff;
  border:1px solid var(--cx-line);
  border-radius:9px;
  padding:9px 13px;
  font-size:11.5px;
  font-weight:600;
  letter-spacing:0.13em;
  text-align:left;
  justify-content:flex-start;
  transition:border-color .15s, background .15s, box-shadow .15s;
}
.stButton>button p{font-size:11.5px;letter-spacing:0.13em;font-weight:600;}
.stButton>button:hover{
  background:rgba(14,52,88,0.9);
  border-color:var(--cx-line-strong);
  color:#ffffff;
  box-shadow:0 0 16px rgba(56,189,248,0.22);
}
.stButton>button:focus-visible{outline:2px solid var(--cx-accent);outline-offset:2px;}
.stButton>button[kind="primary"],
.stButton>button[data-testid="stBaseButton-primary"]{
  background:linear-gradient(90deg,rgba(56,189,248,0.30),rgba(34,211,238,0.08));
  border-color:var(--cx-accent);
  color:#ffffff;
  box-shadow:inset 3px 0 0 var(--cx-accent), 0 0 18px rgba(56,189,248,0.28);
}

/* ---------------- inputs ---------------- */
label, .stSelectbox label, .stMultiSelect label, .stTextInput label, .stSlider label{
  color:var(--cx-muted) !important;
  font-size:10px !important;
  letter-spacing:0.16em !important;
  text-transform:uppercase;
  font-weight:600 !important;
}
[data-baseweb="select"]>div{
  background:var(--cx-panel-2) !important;
  border-color:var(--cx-line) !important;
  border-radius:9px !important;
  color:var(--cx-text) !important;
}
[data-baseweb="select"] svg{color:var(--cx-accent) !important;}
[data-baseweb="popover"] [role="listbox"], [data-baseweb="menu"]{
  background:#061223 !important;
  border:1px solid var(--cx-line) !important;
}
[data-baseweb="menu"] li{color:#cfe4f7 !important;}
[data-baseweb="menu"] li:hover{background:rgba(56,189,248,0.14) !important;}
[data-baseweb="tag"]{background:rgba(56,189,248,0.18) !important;border:1px solid var(--cx-line) !important;color:#dcf0ff !important;}
.stTextInput input, .stNumberInput input{
  background:var(--cx-panel-2) !important;
  color:var(--cx-text) !important;
  border:1px solid var(--cx-line) !important;
  border-radius:9px !important;
}
.stTextInput input::placeholder{color:#4e6c85 !important;}
[data-testid="stSlider"] [role="slider"]{background:var(--cx-accent) !important;}
[data-testid="stExpander"]{
  border:1px solid var(--cx-line) !important;
  border-radius:12px !important;
  background:rgba(7,20,38,0.85) !important;
  overflow:hidden;
}
[data-testid="stExpander"] summary{color:#cfe8ff !important;font-weight:600;letter-spacing:0.04em;}
[data-testid="stExpander"] summary:hover{color:#ffffff !important;}
[data-testid="stCaptionContainer"], .stCaption{color:var(--cx-dim) !important;}
.stAlert{background:rgba(7,20,38,0.9) !important;border:1px solid var(--cx-line) !important;color:#cfe4f7 !important;}

/* ---------------- hero ---------------- */
.cx-hero{
  display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:18px;
  padding:14px 4px 20px 4px;
}
.cx-hero-id{display:flex;align-items:center;gap:16px;}
.cx-hero-id .cx-mark{width:54px;height:54px;flex:none;}
.cx-wordmark{font-family:'Orbitron',sans-serif;font-size:34px;font-weight:800;letter-spacing:3px;color:#f4fbff;line-height:1;}
.cx-wordmark em{color:var(--cx-accent);font-style:normal;text-shadow:0 0 18px rgba(56,189,248,0.6);}
.cx-role{font-family:'Orbitron',sans-serif;font-size:12.5px;letter-spacing:0.34em;color:var(--cx-accent-2);margin-top:8px;}
.cx-tagline{font-size:12.5px;color:var(--cx-muted);margin-top:6px;max-width:62ch;}

.cx-hero-stats{
  display:flex;align-items:stretch;gap:0;
  border:1px solid var(--cx-line);border-radius:12px;
  background:rgba(7,20,38,0.8);
  box-shadow:0 0 26px rgba(0,110,200,0.14);
  overflow:hidden;
}
.cx-hero-stat{padding:11px 20px;border-right:1px solid rgba(56,189,248,0.14);min-width:120px;}
.cx-hero-stat:last-child{border-right:none;}
.cx-hero-stat .k{font-size:9px;letter-spacing:0.2em;color:var(--cx-dim);}
.cx-hero-stat .v{font-size:13px;color:#e4f2ff;margin-top:6px;font-weight:600;letter-spacing:0.03em;}
.cx-hero-stat .v.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:12px;}
.cx-online{color:#22d3ee;text-shadow:0 0 9px rgba(34,211,238,0.75);}

/* ---------------- threat operations ---------------- */
.cx-ops{
  position:relative;
  border:1px solid var(--cx-line-strong);
  border-radius:18px;
  padding:44px 24px 26px 24px;
  margin:22px 0 20px 0;
  background:linear-gradient(180deg,rgba(6,32,62,0.92),rgba(3,13,28,0.96));
  box-shadow:0 0 34px rgba(0,116,214,0.18), inset 0 0 60px rgba(0,110,255,0.05);
}
.cx-ops-chip{
  position:absolute;top:-16px;left:50%;transform:translateX(-50%);
  padding:7px 46px;border-radius:30px;
  background:linear-gradient(90deg,#0b6fc4,#22d3ee,#0b6fc4);
  border:1px solid #6fdcff;
  font-family:'Orbitron',sans-serif;font-size:13px;font-weight:700;letter-spacing:0.28em;
  color:#03121f;white-space:nowrap;
  box-shadow:0 0 22px rgba(34,211,238,0.5);
}
.cx-metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(198px,1fr));gap:18px;}
.cx-metric{
  position:relative;text-align:center;
  border:1px solid var(--cx-line);border-radius:12px;
  background:linear-gradient(180deg,rgba(10,32,60,0.9),rgba(4,16,32,0.9));
  padding:30px 12px 18px 12px;
}
.cx-metric-icon{
  position:absolute;top:-23px;left:50%;transform:translateX(-50%);
  width:46px;height:46px;border-radius:50%;
  display:flex;align-items:center;justify-content:center;font-size:20px;
  background:#04182f;border:1px solid var(--cx-accent);
  box-shadow:0 0 18px rgba(56,189,248,0.45);
}
.cx-metric-value{font-family:'Orbitron',sans-serif;font-size:38px;font-weight:700;color:#f6fcff;text-shadow:0 0 16px rgba(56,189,248,0.45);line-height:1.1;}
.cx-metric-label{font-size:11px;letter-spacing:0.18em;color:#bfe0f7;margin-top:6px;}
.cx-metric-note{font-size:10px;color:var(--cx-dim);margin-top:5px;letter-spacing:0.04em;}

/* ---------------- kpi row ---------------- */
.cx-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px;margin-bottom:20px;}
.cx-kpi{
  border:1px solid var(--cx-line);border-left:3px solid var(--cx-accent);
  border-radius:12px;padding:16px 18px;
  background:linear-gradient(120deg,rgba(10,25,47,0.95),rgba(4,14,28,0.95));
}
.cx-kpi .k{font-size:10px;letter-spacing:0.2em;color:var(--cx-muted);}
.cx-kpi .v{font-family:'Orbitron',sans-serif;font-size:31px;font-weight:700;color:#f3faff;margin-top:8px;line-height:1;}
.cx-kpi .n{font-size:10.5px;color:var(--cx-dim);margin-top:7px;}

/* ---------------- panels ---------------- */
.cx-panel{
  border:1px solid var(--cx-line);border-radius:14px;
  background:linear-gradient(180deg,rgba(7,20,38,0.96),rgba(3,12,26,0.98));
  box-shadow:0 0 24px rgba(0,96,190,0.10);
  margin-bottom:18px;overflow:hidden;
}
.cx-panel-head{
  display:flex;align-items:center;justify-content:space-between;gap:12px;
  padding:11px 16px;border-bottom:1px solid var(--cx-line);
  background:linear-gradient(90deg,rgba(11,64,116,0.55),rgba(7,20,38,0));
}
.cx-panel-title{font-family:'Orbitron',sans-serif;font-size:12.5px;font-weight:700;letter-spacing:0.2em;color:#e2f3ff;display:flex;align-items:center;gap:9px;}
.cx-panel-sub{font-size:9.5px;letter-spacing:0.16em;color:var(--cx-dim);text-align:right;}
.cx-panel-body{padding:16px;}
.cx-empty{
  border:1px dashed var(--cx-line);border-radius:10px;
  padding:26px 16px;text-align:center;color:var(--cx-muted);font-size:12.5px;
  background:rgba(4,14,28,0.6);
}
.cx-empty b{display:block;color:#cfe6fb;font-size:13px;margin-bottom:5px;letter-spacing:0.08em;}

/* ---------------- bars ---------------- */
.cx-bar-row{display:grid;grid-template-columns:minmax(96px,34%) 1fr 52px;align-items:center;gap:12px;margin-bottom:11px;}
.cx-bar-label{font-size:11.5px;color:#cbe3f6;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.cx-bar-track{height:10px;border-radius:6px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.12);overflow:hidden;}
.cx-bar-fill{height:100%;border-radius:6px;}
.cx-bar-value{font-family:'Orbitron',sans-serif;font-size:13px;color:#eaf6ff;text-align:right;}

/* ---------------- tables ---------------- */
.cx-scroll{overflow-x:auto;}
.cx-table{width:100%;border-collapse:collapse;font-size:12px;}
.cx-table th{
  text-align:left;padding:9px 11px;white-space:nowrap;
  font-size:9.5px;letter-spacing:0.18em;color:var(--cx-muted);
  border-bottom:1px solid var(--cx-line);
}
.cx-table td{padding:9px 11px;border-bottom:1px solid rgba(56,189,248,0.08);color:#d9ebfb;vertical-align:middle;white-space:nowrap;}
.cx-table tr:last-child td{border-bottom:none;}
.cx-table tbody tr:hover td{background:rgba(56,189,248,0.07);}
.cx-table td.mono, .cx-table td .mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:#a9cbe6;}
.cx-table td.wrap{white-space:normal;}

.cx-badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:9.5px;font-weight:700;letter-spacing:0.12em;border:1px solid;}
.cx-risk{display:flex;align-items:center;gap:8px;}
.cx-risk-track{width:54px;height:5px;border-radius:4px;background:rgba(56,189,248,0.12);overflow:hidden;}
.cx-risk-fill{height:100%;}
.cx-risk-num{font-family:'Orbitron',sans-serif;font-size:11px;color:#dff0ff;}

/* ---------------- alert cards ---------------- */
.cx-alert{
  border:1px solid rgba(56,189,248,0.16);border-left-width:3px;border-radius:10px;
  background:rgba(6,20,40,0.9);padding:11px 14px;margin-bottom:10px;
}
.cx-alert.sel{background:rgba(14,52,88,0.75);border-color:var(--cx-accent);box-shadow:0 0 16px rgba(56,189,248,0.2);}
.cx-alert-top{display:flex;justify-content:space-between;align-items:center;gap:10px;}
.cx-alert-id{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:10px;color:var(--cx-dim);}
.cx-alert-title{font-size:13px;color:#e7f4ff;margin-top:7px;font-weight:500;}
.cx-alert-meta{font-size:10px;color:var(--cx-dim);margin-top:6px;letter-spacing:0.05em;}

/* ---------------- key/value grid ---------------- */
.cx-kv{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:1px;background:rgba(56,189,248,0.1);border:1px solid var(--cx-line);border-radius:10px;overflow:hidden;}
.cx-kv-item{background:#061423;padding:11px 14px;min-height:56px;}
.cx-kv-item .k{font-size:9px;letter-spacing:0.18em;color:var(--cx-dim);}
.cx-kv-item .v{font-size:12.5px;color:#dceefc;margin-top:6px;word-break:break-word;}
.cx-kv-item .v.mono{font-family:ui-monospace,SFMono-Regular,Consolas,monospace;font-size:11px;color:#a9cbe6;}
.cx-kv-item.wide{grid-column:1/-1;}

/* ---------------- chart ---------------- */
.cx-chart{width:100%;height:auto;display:block;}
.cx-legend{display:flex;gap:18px;align-items:center;justify-content:flex-end;margin-bottom:6px;}
.cx-legend span{font-size:10px;letter-spacing:0.12em;color:var(--cx-muted);display:flex;align-items:center;gap:7px;}
.cx-legend i{width:16px;height:3px;border-radius:2px;display:inline-block;}

.cx-section{font-family:'Orbitron',sans-serif;font-size:12px;letter-spacing:0.24em;color:var(--cx-accent-2);margin:6px 0 12px 2px;}
.cx-foot{text-align:center;color:var(--cx-dim);font-size:10px;letter-spacing:0.14em;padding:18px 0 4px 0;border-top:1px solid rgba(56,189,248,0.1);margin-top:14px;}

@media (max-width:1400px){
  .cx-wordmark{font-size:28px;}
  .cx-metric-value{font-size:32px;}
  .block-container{padding-left:18px;padding-right:18px;}
}
@media (max-width:1100px){
  .cx-hero{flex-direction:column;align-items:flex-start;}
  .cx-hero-stats{flex-wrap:wrap;}
  .cx-bar-row{grid-template-columns:minmax(80px,42%) 1fr 44px;}
}
@media (prefers-reduced-motion:reduce){
  *{transition:none !important;animation:none !important;}
}
</style>
"""

SHIELD_MARK = (
    '<svg class="cx-mark" viewBox="0 0 48 56" xmlns="http://www.w3.org/2000/svg" '
    'aria-hidden="true">'
    '<defs><linearGradient id="cxShield" x1="0" y1="0" x2="0" y2="1">'
    '<stop offset="0%" stop-color="#5ad4ff"/><stop offset="100%" stop-color="#0a5ba8"/>'
    "</linearGradient></defs>"
    '<path d="M24 1 45 9v20c0 12-9 21-21 26C12 50 3 41 3 29V9z" fill="url(#cxShield)" '
    'opacity="0.22"/>'
    '<path d="M24 1 45 9v20c0 12-9 21-21 26C12 50 3 41 3 29V9z" fill="none" '
    'stroke="#4cc9ff" stroke-width="2"/>'
    '<path d="M24 12v32" stroke="#bdeaff" stroke-width="1.4" opacity="0.6"/>'
    '<path d="M14 21h20M11 29h26M14 37h20" stroke="#7fdcff" stroke-width="1.6" '
    'stroke-linecap="round"/>'
    "</svg>"
)


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------

_NESTED_KEYS = (
    "process",
    "process_info",
    "data",
    "details",
    "detail",
    "event",
    "metadata",
    "meta",
    "fields",
    "context",
    "attributes",
    "info",
    "file",
)


def _containers(record):
    """Yield the record itself plus one level of common nested dictionaries."""
    yield record
    for key in _NESTED_KEYS:
        nested = record.get(key)
        if isinstance(nested, dict):
            yield nested


def pick(record, *keys, default=None):
    """First non-empty value for any of ``keys``, searched one level deep."""
    if not isinstance(record, dict):
        return default
    for container in _containers(record):
        for key in keys:
            if key in container:
                value = container[key]
                if value is None:
                    continue
                if isinstance(value, (str, list, tuple, dict)) and len(value) == 0:
                    continue
                return value
    return default


def as_text(value, limit=None):
    """Flatten any JSON value to a single readable line."""
    if value is None:
        text = ""
    elif isinstance(value, bool):
        text = "true" if value else "false"
    elif isinstance(value, (list, tuple)):
        text = " ".join(as_text(item) for item in value)
    elif isinstance(value, dict):
        text = json.dumps(value, default=str)
    else:
        text = str(value)
    text = " ".join(text.split())
    if limit and len(text) > limit:
        text = text[: limit - 1].rstrip() + "\u2026"
    return text


def to_int(value, default=None):
    try:
        if isinstance(value, bool):
            return default
        return int(float(value))
    except (TypeError, ValueError):
        return default


def to_float(value, default=0.0):
    try:
        if isinstance(value, bool):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def norm_severity(value):
    """Normalise whatever the engine wrote into one of SEVERITY_ORDER."""
    if value is None:
        return "unknown"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return "unknown"
    key = str(value).strip().lower().replace("-", "_").replace(" ", "_")
    if not key:
        return "unknown"
    if key in SEVERITY_ALIASES:
        return SEVERITY_ALIASES[key]
    for alias, canonical in SEVERITY_ALIASES.items():
        if key.startswith(alias):
            return canonical
    return "unknown"


def worst_severity(values, default="unknown"):
    """Most severe entry in ``values``, ranked by SEVERITY_ORDER."""
    present = {norm_severity(value) for value in values}
    for name in SEVERITY_ORDER:
        if name in present:
            return name
    return default


def severity_color(severity):
    return SEVERITY_COLORS.get(severity, SEVERITY_COLORS["unknown"])


def parse_ts(value):
    """Parse ISO-8601, epoch seconds/milliseconds or common datetime strings."""
    moment = None
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        seconds = float(value)
        if seconds > 1e11:
            seconds /= 1000.0
        try:
            moment = datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError:
            for fmt in (
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
                "%Y/%m/%d %H:%M:%S",
                "%m/%d/%Y %H:%M:%S",
                "%Y%m%dT%H%M%S",
            ):
                try:
                    moment = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    try:
        return moment.astimezone()
    except (OverflowError, OSError, ValueError):
        return moment


def fmt_clock(moment):
    return moment.strftime("%H:%M:%S") if moment else "\u2014"


def fmt_stamp(moment):
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment else "\u2014"


def fmt_day(moment):
    return moment.strftime("%Y-%m-%d") if moment else "\u2014"


def fmt_count(value):
    return f"{value:,}"


# --------------------------------------------------------------------------
# Data layer
# --------------------------------------------------------------------------


def resolve_events_file():
    """Locate events.jsonl without ever writing to it."""
    override = os.environ.get("CIPHER_X_EVENTS")
    if override:
        return Path(override).expanduser()
    candidates = (
        DEFAULT_EVENTS_FILE,
        Path.cwd() / "data" / "events.jsonl",
        BASE_DIR / "events.jsonl",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return DEFAULT_EVENTS_FILE


def read_jsonl(path):
    """Read the event log, skipping malformed lines instead of failing."""
    records = []
    malformed = 0
    if not path.exists():
        return records, malformed
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                if isinstance(parsed, dict):
                    records.append(parsed)
                elif isinstance(parsed, list):
                    records.extend(item for item in parsed if isinstance(item, dict))
                else:
                    malformed += 1
    except OSError:
        return records, malformed
    return records, malformed


def extract_detections(record):
    """Pull detection objects out of an event in whatever shape they were written.

    Alerts (security_alert, correlation_alert) commonly carry the process
    context that triggered them - process, PID, parent, username, command
    line - only inside the embedded detection object, not on the alert
    itself. Each detection dict below carries that context too, so
    normalize_event() can fall back to it when the alert record has none.
    """
    raw = record.get("detections")
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        single = record.get("detection")
        raw = [single] if isinstance(single, dict) else []

    found = []
    for item in raw:
        if isinstance(item, str):
            item = {"rule": item}
        if not isinstance(item, dict):
            continue
        found.append(
            {
                "rule": as_text(
                    pick(item, "rule", "rule_name", "name", "detection_rule", default="unknown")
                ),
                "severity": norm_severity(pick(item, "severity", "risk_level", "level")),
                "mitre_id": as_text(
                    pick(item, "mitre_technique_id", "technique_id", "mitre_id", default="")
                ),
                "mitre_name": as_text(
                    pick(item, "mitre_technique_name", "technique_name", "mitre_name", default="")
                ),
                "description": as_text(pick(item, "description", "details", "message", default="")),
                "risk": to_float(pick(item, "risk_score", "risk", "score"), 0.0),
                "process": as_text(
                    pick(item, "process_name", "process", "image_name", "proc_name", default="")
                ),
                "parent": as_text(
                    pick(
                        item,
                        "parent_process_name",
                        "parent_process",
                        "parent_name",
                        "parent_image",
                        default="",
                    )
                ),
                "pid": to_int(pick(item, "pid", "process_id")),
                "ppid": to_int(pick(item, "ppid", "parent_pid", "parent_process_id")),
                "username": as_text(
                    pick(item, "username", "user", "user_name", "account", default="")
                ),
                "command_line": as_text(
                    pick(item, "command_line", "cmdline", "cmd", "command", "args", default="")
                ),
            }
        )

    if not found:
        rule = pick(record, "rule", "rule_name", "detection_rule")
        if rule:
            found.append(
                {
                    "rule": as_text(rule),
                    "severity": norm_severity(pick(record, "severity", "risk_level", "level")),
                    "mitre_id": as_text(
                        pick(record, "mitre_technique_id", "technique_id", "mitre_id", default="")
                    ),
                    "mitre_name": as_text(
                        pick(record, "mitre_technique_name", "technique_name", default="")
                    ),
                    "description": as_text(pick(record, "description", "message", default="")),
                    "risk": to_float(pick(record, "risk_score", "risk", "score"), 0.0),
                    "process": as_text(
                        pick(record, "process_name", "process", "image_name", "proc_name", default="")
                    ),
                    "parent": as_text(
                        pick(
                            record,
                            "parent_process_name",
                            "parent_process",
                            "parent_name",
                            "parent_image",
                            default="",
                        )
                    ),
                    "pid": to_int(pick(record, "pid", "process_id")),
                    "ppid": to_int(pick(record, "ppid", "parent_pid", "parent_process_id")),
                    "username": as_text(
                        pick(record, "username", "user", "user_name", "account", default="")
                    ),
                    "command_line": as_text(
                        pick(record, "command_line", "cmdline", "cmd", "command", "args", default="")
                    ),
                }
            )
    return found


def first_detection_value(detections, key):
    """First non-empty value for ``key`` across the event's detection objects,
    in the order they were written. Returns None if none of them have it -
    callers must not invent a value when this comes back empty."""
    for det in detections:
        value = det.get(key)
        if value not in (None, ""):
            return value
    return None


def normalize_event(record, index):
    """Flatten one raw log line into the shape the dashboard renders."""
    moment = parse_ts(
        pick(record, "timestamp", "time", "@timestamp", "event_time", "created_at", "datetime")
    )
    detections = extract_detections(record)

    severity = norm_severity(pick(record, "severity", "risk_level", "level", "priority"))
    if severity == "unknown" and detections:
        severity = worst_severity(det["severity"] for det in detections)

    risk = to_float(pick(record, "risk_score", "risk", "score"), 0.0)
    if not risk and detections:
        risk = max(det["risk"] for det in detections)

    # Alerts and correlation alerts often carry only the alert-level fields
    # (title, severity, status, risk) and leave the process context - who
    # ran what, PID, parent, command line - inside the embedded detection
    # instead. Read the alert's own top-level field first; only fall back
    # to the first detection object that actually has the field. If
    # neither has it, it stays empty/None and renders as the dash - never
    # fabricated.
    process = as_text(
        pick(record, "process_name", "process", "image_name", "proc_name", default="")
    )
    if not process:
        process = as_text(first_detection_value(detections, "process") or "")

    parent = as_text(
        pick(
            record,
            "parent_process_name",
            "parent_process",
            "parent_name",
            "parent_image",
            default="",
        )
    )
    if not parent:
        parent = as_text(first_detection_value(detections, "parent") or "")

    pid = to_int(pick(record, "pid", "process_id"))
    if pid is None:
        pid = first_detection_value(detections, "pid")

    ppid = to_int(pick(record, "ppid", "parent_pid", "parent_process_id"))
    if ppid is None:
        ppid = first_detection_value(detections, "ppid")

    username = as_text(pick(record, "username", "user", "user_name", "account", default=""))
    if not username:
        username = as_text(first_detection_value(detections, "username") or "")

    command_line = as_text(
        pick(record, "command_line", "cmdline", "cmd", "command", "args", default="")
    )
    if not command_line:
        command_line = as_text(first_detection_value(detections, "command_line") or "")

    return {
        "seq": index,
        "raw": record,
        "event_type": as_text(pick(record, "event_type", "type", "kind", default="unknown")).lower(),
        "ts": moment,
        "ts_raw": as_text(pick(record, "timestamp", "time", "@timestamp", default="")),
        "process": process,
        "parent": parent,
        "pid": pid,
        "ppid": ppid,
        "username": username,
        "hostname": as_text(
            pick(
                record,
                "hostname",
                "host",
                "host_name",
                "computer_name",
                "machine_name",
                "machine",
                "endpoint",
                "endpoint_id",
                "device_name",
                default="",
            )
        ),
        "executable": as_text(
            pick(record, "executable", "exe", "image", "process_path", "executable_path", default="")
        ),
        "command_line": command_line,
        "file_path": as_text(
            pick(record, "file_path", "target_path", "path", "filename", "file_name", default="")
        ),
        "file_hash": as_text(
            pick(record, "sha256", "file_hash", "hash", "sha1", "md5", default="")
        ),
        "file_action": as_text(
            pick(record, "action", "change_type", "operation", "file_action", default="")
        ),
        "alert_id": as_text(pick(record, "alert_id", "id", "uuid", "event_id", default="")),
        "title": as_text(pick(record, "title", "alert_title", "summary", "name", default="")),
        "status": as_text(pick(record, "status", "state", default="")).lower(),
        "description": as_text(pick(record, "description", "message", "details", default="")),
        "severity": severity,
        "risk": risk,
        "detections": detections,
    }


def normalize_events(records):
    events = [normalize_event(record, index) for index, record in enumerate(records)]
    events.sort(key=lambda event: (event["ts"] or EPOCH, event["seq"]))
    return events


@st.cache_data(show_spinner=False)
def load_events(path_str, mtime, size):
    """Cached on the log's mtime/size so a refresh picks up new telemetry."""
    records, malformed = read_jsonl(Path(path_str))
    return normalize_events(records), malformed


def file_signature(path):
    try:
        stat = path.stat()
        return stat.st_mtime, stat.st_size
    except OSError:
        return 0.0, 0


def of_type(events, types):
    return [event for event in events if event["event_type"] in types]


def is_open(alert):
    return alert["status"] not in RESOLVED_STATUSES


def detection_rows(events):
    """One row per detection object inside every detection-bearing event."""
    rows = []
    for event in events:
        for det in event["detections"]:
            rows.append(
                {
                    "ts": event["ts"],
                    "event_type": event["event_type"],
                    "rule": det["rule"] or "unknown",
                    "severity": det["severity"],
                    "mitre_id": det["mitre_id"],
                    "mitre_name": det["mitre_name"],
                    "description": det["description"],
                    "process": event["process"],
                    "parent": event["parent"],
                    "pid": event["pid"],
                    "ppid": event["ppid"],
                    "username": event["username"],
                    "command_line": event["command_line"],
                    "risk": det["risk"] or event["risk"],
                    "event": event,
                }
            )
    return rows


def get_metrics(events):
    """Every figure on screen comes from this one pass over the log."""
    processes = of_type(events, PROCESS_TYPES)
    detections = of_type(events, DETECTION_TYPES)
    alerts = of_type(events, ALERT_TYPES)
    correlations = of_type(events, CORRELATION_TYPES)
    file_events = of_type(events, FILE_TYPES)

    # Alerts and correlation alerts wrap a detection that was already logged
    # as its own security_detection event, so counting their embedded copy
    # would double count the rule hit. Statistics use detection events only;
    # alerts stay counted as alerts and keep their detection for display.
    rows = detection_rows(of_type(events, RULE_HIT_TYPES))

    hostnames = {event["hostname"] for event in events if event["hostname"]}
    if not hostnames:
        # No hostname field in this schema: the agent reports one local endpoint.
        derived = {
            event["username"].split("\\")[0]
            for event in events
            if "\\" in event["username"]
        }
        hostnames = derived

    usernames = {event["username"] for event in events if event["username"]}

    stamps = [event["ts"] for event in events if event["ts"]]
    latest = max(stamps) if stamps else None
    earliest = min(stamps) if stamps else None

    # Anchor the 24h window on the newest telemetry so a stale log still
    # reports its own last day rather than a misleading zero.
    now = datetime.now(timezone.utc).astimezone()
    anchor = max(latest, now) if latest else now
    window_start = anchor - timedelta(hours=24)
    recent = [event for event in events if event["ts"] and event["ts"] >= window_start]

    open_alerts = [alert for alert in alerts if is_open(alert)]

    severity_source = "security alerts"
    severity_pool = [alert["severity"] for alert in alerts + correlations]
    if not any(value != "unknown" for value in severity_pool):
        severity_pool = [row["severity"] for row in rows]
        severity_source = "security detections"
    severity_counts = OrderedDict(
        (name, sum(1 for value in severity_pool if value == name)) for name in SEVERITY_ORDER
    )

    risks = [row["risk"] for row in rows if row["risk"]]

    return {
        "events": events,
        "processes": processes,
        "detections": detections,
        "alerts": alerts,
        "correlations": correlations,
        "file_events": file_events,
        "rows": rows,
        "hostnames": sorted(hostnames),
        "endpoint": sorted(hostnames)[0] if hostnames else "LOCAL ENDPOINT",
        "machines": len(hostnames) if hostnames else (1 if events else 0),
        "users": sorted(usernames),
        "latest": latest,
        "earliest": earliest,
        "recent": recent,
        "window_start": window_start,
        "open_alerts": open_alerts,
        "severity_counts": severity_counts,
        "severity_source": severity_source,
        "critical_high": severity_counts["critical"] + severity_counts["high"],
        "avg_risk": round(sum(risks) / len(risks), 1) if risks else 0.0,
        "max_risk": round(max(risks), 1) if risks else 0.0,
        "event_types": Counter(event["event_type"] for event in events),
    }


# --------------------------------------------------------------------------
# HTML primitives
#
# Every block below is emitted as one balanced string in a single
# st.markdown call. Nothing opens a tag in one call and closes it in
# another, which is what makes stray </div> text show up on screen.
# --------------------------------------------------------------------------


def html_block(markup):
    return "".join(line.strip() for line in markup.splitlines())


def render_html(markup):
    st.markdown(html_block(markup), unsafe_allow_html=True)


def esc(value, limit=None):
    return escape(as_text(value, limit), quote=True)


def panel_html(title, body, icon="", subtitle=""):
    return (
        '<div class="cx-panel">'
        '<div class="cx-panel-head">'
        f'<div class="cx-panel-title"><span>{icon}</span>{escape(title)}</div>'
        f'<div class="cx-panel-sub">{escape(subtitle)}</div>'
        "</div>"
        f'<div class="cx-panel-body">{body}</div>'
        "</div>"
    )


def panel(title, body, icon="", subtitle=""):
    render_html(panel_html(title, body, icon, subtitle))


def empty_state(headline, detail=""):
    return f'<div class="cx-empty"><b>{escape(headline)}</b>{escape(detail)}</div>'


def badge(severity):
    color = severity_color(severity)
    return (
        f'<span class="cx-badge" style="color:{color};border-color:{color}66;'
        f'background:{color}1f">{severity.upper()}</span>'
    )


def risk_cell(value, ceiling=RISK_SCORE_CEILING):
    number = to_float(value, 0.0)
    pct = 0 if ceiling <= 0 else max(0.0, min(100.0, number / ceiling * 100.0))
    color = "#ff4d6d" if pct >= 75 else "#ff9f45" if pct >= 50 else ACCENT
    return (
        '<span class="cx-risk">'
        f'<span class="cx-risk-track"><span class="cx-risk-fill" style="width:{pct:.0f}%;'
        f'background:{color};box-shadow:0 0 8px {color}88"></span></span>'
        f'<span class="cx-risk-num">{number:g}</span>'
        "</span>"
    )


def bar_row(label, value, total, color=ACCENT, title=None):
    width = 0.0 if not total else max(2.0, value / total * 100.0)
    return (
        f'<div class="cx-bar-row" title="{escape(title or label)}">'
        f'<div class="cx-bar-label">{escape(label)}</div>'
        '<div class="cx-bar-track">'
        f'<div class="cx-bar-fill" style="width:{width:.1f}%;'
        f"background:linear-gradient(90deg,{color}33,{color});"
        f'box-shadow:0 0 12px {color}66"></div>'
        "</div>"
        f'<div class="cx-bar-value">{fmt_count(value)}</div>'
        "</div>"
    )


def table(columns, rows):
    """rows: list of lists of already-escaped HTML cells."""
    if not rows:
        return empty_state("Nothing to show", "No records match the current view.")
    head = "".join(f"<th>{escape(column)}</th>" for column in columns)
    body = "".join(
        "<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows
    )
    return (
        f'<div class="cx-scroll"><table class="cx-table"><thead><tr>{head}</tr></thead>'
        f"<tbody>{body}</tbody></table></div>"
    )


def kv(label, value, mono=False, full_width=False):
    """One field for kv_grid. ``mono`` sets the typeface, ``full_width``
    the layout: they are independent."""
    return {"label": label, "value": value, "mono": mono, "full_width": full_width}


def kv_grid(fields):
    items = []
    for field in fields:
        item_class = "cx-kv-item wide" if field["full_width"] else "cx-kv-item"
        value_class = "v mono" if field["mono"] else "v"
        text = as_text(field["value"]) or DASH
        items.append(
            f'<div class="{item_class}"><div class="k">{escape(field["label"])}</div>'
            f'<div class="{value_class}">{escape(text)}</div></div>'
        )
    return '<div class="cx-kv">' + "".join(items) + "</div>"


def metric_card(icon, value, label, note=""):
    return (
        '<div class="cx-metric">'
        f'<div class="cx-metric-icon">{icon}</div>'
        f'<div class="cx-metric-value">{escape(value)}</div>'
        f'<div class="cx-metric-label">{escape(label)}</div>'
        f'<div class="cx-metric-note">{escape(note)}</div>'
        "</div>"
    )


def kpi_card(label, value, note="", color=ACCENT):
    return (
        f'<div class="cx-kpi" style="border-left-color:{color}">'
        f'<div class="k">{escape(label)}</div>'
        f'<div class="v" style="text-shadow:0 0 16px {color}55">{escape(value)}</div>'
        f'<div class="n">{escape(note)}</div>'
        "</div>"
    )


# --------------------------------------------------------------------------
# Time bucketing + inline SVG chart
# --------------------------------------------------------------------------

STEP_CHOICES = (
    (timedelta(minutes=1), "%H:%M", "1 min"),
    (timedelta(minutes=5), "%H:%M", "5 min"),
    (timedelta(minutes=15), "%H:%M", "15 min"),
    (timedelta(hours=1), "%H:%M", "hourly"),
    (timedelta(hours=6), "%m/%d %H:%M", "6 hour"),
    (timedelta(days=1), "%m/%d", "daily"),
    (timedelta(days=7), "%m/%d", "weekly"),
    (timedelta(days=30), "%b %Y", "monthly"),
)


def floor_moment(moment, step):
    if step >= timedelta(days=1):
        midnight = moment.replace(hour=0, minute=0, second=0, microsecond=0)
        days = max(1, step.days)
        if days > 1:
            offset = (midnight.date() - EPOCH.date()).days % days
            midnight -= timedelta(days=offset)
        return midnight
    seconds = int(step.total_seconds())
    elapsed = int((moment - EPOCH).total_seconds())
    return (EPOCH + timedelta(seconds=elapsed - (elapsed % seconds))).astimezone()


def bucket_series(primary_events, secondary_events=(), max_buckets=MAX_CHART_BUCKETS):
    """Group events into evenly spaced buckets sized to the real data span."""
    stamps = [event["ts"] for event in primary_events if event["ts"]]
    if not stamps:
        return [], ""
    start, end = min(stamps), max(stamps)
    span = end - start
    step, fmt, name = STEP_CHOICES[-1]
    for candidate, candidate_fmt, candidate_name in STEP_CHOICES:
        if span <= candidate * max_buckets:
            step, fmt, name = candidate, candidate_fmt, candidate_name
            break
    else:
        # Longer than the widest interval can cover: widen it until it fits.
        multiplier = int(span / (step * max_buckets)) + 1
        step = step * multiplier
        name = f"{multiplier} x {name}"

    keys = []
    cursor = floor_moment(start, step)
    stop = floor_moment(end, step)
    while cursor <= stop and len(keys) < max_buckets:
        keys.append(cursor)
        cursor = floor_moment(cursor + step, step)
    if not keys:
        keys = [floor_moment(start, step)]

    primary = Counter(floor_moment(stamp, step) for stamp in stamps)
    secondary = Counter(
        floor_moment(event["ts"], step) for event in secondary_events if event["ts"]
    )
    series = [
        (key.strftime(fmt), primary.get(key, 0), secondary.get(key, 0)) for key in keys
    ]
    return series, f"{name} buckets"


def nice_top(value):
    value = max(1, int(value))
    if value <= 5:
        return value
    magnitude = 10 ** (len(str(value)) - 1)
    for multiplier in (1, 1.5, 2, 2.5, 4, 5, 7.5, 10):
        candidate = int(magnitude * multiplier)
        if candidate >= value:
            return candidate
    return value


def timeseries_svg(series, uid, primary_color=ACCENT, secondary_color="#ff9f45"):
    """Hand-built SVG so the chart matches the console, not Streamlit's default."""
    width, height = 960, 250
    pad_l, pad_r, pad_t, pad_b = 52, 16, 16, 30
    inner_w = width - pad_l - pad_r
    inner_h = height - pad_t - pad_b
    count = len(series)
    top = nice_top(max([row[1] for row in series] + [row[2] for row in series] + [1]))

    def x_at(index):
        if count <= 1:
            return pad_l + inner_w / 2
        return pad_l + inner_w * index / (count - 1)

    def y_at(value):
        return pad_t + inner_h - (value / top) * inner_h

    parts = [
        f'<svg class="cx-chart" viewBox="0 0 {width} {height}" '
        'xmlns="http://www.w3.org/2000/svg" role="img">',
        f'<defs><linearGradient id="cxFill{uid}" x1="0" y1="0" x2="0" y2="1">'
        f'<stop offset="0%" stop-color="{primary_color}" stop-opacity="0.45"/>'
        f'<stop offset="100%" stop-color="{primary_color}" stop-opacity="0"/>'
        "</linearGradient></defs>",
    ]

    for step_index in range(5):
        value = top * step_index / 4
        y = y_at(value)
        parts.append(
            f'<line x1="{pad_l}" y1="{y:.1f}" x2="{width - pad_r}" y2="{y:.1f}" '
            'stroke="rgba(56,189,248,0.13)" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{pad_l - 10}" y="{y + 4:.1f}" text-anchor="end" '
            f'fill="#6d8ea8" font-size="10" font-family="Inter,sans-serif">'
            f"{int(round(value)):,}</text>"
        )

    points = [(x_at(index), y_at(row[1])) for index, row in enumerate(series)]
    baseline = y_at(0)
    if count == 1:
        x, y = points[0]
        parts.append(
            f'<rect x="{x - 26:.1f}" y="{y:.1f}" width="52" height="{baseline - y:.1f}" '
            f'fill="url(#cxFill{uid})" stroke="{primary_color}" stroke-width="2"/>'
        )
    else:
        area = f"M {points[0][0]:.1f},{baseline:.1f} " + " ".join(
            f"L {x:.1f},{y:.1f}" for x, y in points
        )
        area += f" L {points[-1][0]:.1f},{baseline:.1f} Z"
        line = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
        parts.append(f'<path d="{area}" fill="url(#cxFill{uid})"/>')
        parts.append(
            f'<polyline points="{line}" fill="none" stroke="{primary_color}" '
            'stroke-width="7" stroke-opacity="0.18" stroke-linejoin="round"/>'
        )
        parts.append(
            f'<polyline points="{line}" fill="none" stroke="{primary_color}" '
            'stroke-width="2.2" stroke-linejoin="round" stroke-linecap="round"/>'
        )

    if any(row[2] for row in series) and count > 1:
        second = " ".join(
            f"{x_at(index):.1f},{y_at(row[2]):.1f}" for index, row in enumerate(series)
        )
        parts.append(
            f'<polyline points="{second}" fill="none" stroke="{secondary_color}" '
            'stroke-width="2" stroke-dasharray="5 4" stroke-linejoin="round"/>'
        )

    if count <= CHART_POINT_MARKER_LIMIT:
        for index, row in enumerate(series):
            x, y = x_at(index), y_at(row[1])
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.2" fill="#02101f" '
                f'stroke="{primary_color}" stroke-width="2"><title>{escape(row[0])}: '
                f"{row[1]:,} events</title></circle>"
            )

    label_step = max(1, count // 8)
    for index, row in enumerate(series):
        if index % label_step and index != count - 1:
            continue
        parts.append(
            f'<text x="{x_at(index):.1f}" y="{height - 9}" text-anchor="middle" '
            'fill="#6d8ea8" font-size="10" font-family="Inter,sans-serif">'
            f"{escape(row[0])}</text>"
        )

    parts.append("</svg>")
    return "".join(parts)


def chart_legend(pairs):
    items = "".join(
        f'<span><i style="background:{color}"></i>{escape(label)}</span>'
        for label, color in pairs
    )
    return f'<div class="cx-legend">{items}</div>'


# --------------------------------------------------------------------------
# Shared renderers
# --------------------------------------------------------------------------


def primary_detection(event):
    if event["detections"]:
        return event["detections"][0]
    return {
        "rule": event["title"] or "\u2014",
        "severity": event["severity"],
        "mitre_id": "",
        "mitre_name": "",
        "description": event["description"],
        "risk": event["risk"],
    }


def type_label(event_type):
    return event_type.replace("_", " ").upper()


def render_sidebar(metrics, events_path, malformed):
    with st.sidebar:
        render_html(
            '<div class="cx-side-brand">'
            f"{SHIELD_MARK}"
            "<div>"
            f'<div class="cx-side-name">{APP_NAME[:-2]}<em>-X</em></div>'
            '<div class="cx-side-role">ENDPOINT DETECTION &amp; RESPONSE</div>'
            "</div></div>"
        )

        render_html(
            '<div class="cx-side-status">'
            '<span class="cx-dot"></span>'
            '<span class="t">ONLINE</span>'
            f'<span class="s">{escape(fmt_clock(metrics["latest"]))}</span>'
            "</div>"
        )

        rows = (
            ("Telemetry events", len(metrics["events"])),
            ("Security detections", len(metrics["detections"])),
            ("Security alerts", len(metrics["alerts"])),
            ("Correlation alerts", len(metrics["correlations"])),
            ("File events", len(metrics["file_events"])),
        )
        render_html(
            '<div class="cx-side-metrics">'
            + "".join(
                f'<div class="cx-side-metric"><span class="k">{escape(label)}</span>'
                f'<span class="v">{fmt_count(value)}</span></div>'
                for label, value in rows
            )
            + "</div>"
        )

        render_html('<div class="cx-side-label">NAVIGATION</div>')
        for page in PAGES:
            active = st.session_state.page == page.name
            if st.button(
                f"{page.icon}  {page.name}",
                key=f"nav_{page.name}",
                type="primary" if active else "secondary",
            ):
                st.session_state.page = page.name
                st.rerun()

        st.divider()
        if st.button("↻  REFRESH TELEMETRY", key="refresh"):
            st.cache_data.clear()
            st.rerun()
        st.caption(f"Log: {events_path.name}")
        if malformed:
            st.caption(f"{malformed} malformed line(s) skipped")
        render_html(f'<div class="cx-side-foot">{APP_NAME} {APP_VERSION}</div>')


def render_header(metrics):
    stats = (
        ("ENDPOINT", escape(metrics["endpoint"]), ""),
        ("LAST TELEMETRY", escape(fmt_stamp(metrics["latest"])), "mono"),
        ("EVENTS", fmt_count(len(metrics["events"])), ""),
        ("STATUS", '<span class="cx-online">\u25cf</span> ONLINE', ""),
    )
    render_html(
        '<div class="cx-hero">'
        '<div class="cx-hero-id">'
        f"{SHIELD_MARK}"
        "<div>"
        f'<div class="cx-wordmark">{APP_NAME[:-2]}<em>-X</em></div>'
        f'<div class="cx-role">{escape(APP_ROLE.upper())}</div>'
        f'<div class="cx-tagline">{escape(APP_TAGLINE)}</div>'
        "</div></div>"
        '<div class="cx-hero-stats">'
        + "".join(
            f'<div class="cx-hero-stat"><div class="k">{label}</div>'
            f'<div class="v {mono}">{value}</div></div>'
            for label, value, mono in stats
        )
        + "</div></div>"
    )


def render_threat_operations(metrics):
    instances = len(metrics["rows"])
    endpoint_note = metrics["endpoint"] if metrics["hostnames"] else "single local endpoint"
    users = metrics["users"]
    user_note = users[0] if len(users) == 1 else f"{len(users)} accounts seen" if users else "no username field"
    window_note = f"since {fmt_stamp(metrics['window_start'])[5:16]}"

    cards = "".join(
        [
            metric_card(
                "⚠",
                fmt_count(len(metrics["detections"])),
                "ACTIVE DETECTIONS",
                f"{fmt_count(instances)} rule hits",
            ),
            metric_card("◷", fmt_count(len(metrics["recent"])), "RECENT ACTIVITY", window_note),
            metric_card("⌗", fmt_count(metrics["machines"]), "AFFECTED MACHINES", endpoint_note),
            metric_card("⚉", fmt_count(len(users)), "AFFECTED USERS", user_note),
        ]
    )
    render_html(
        '<div class="cx-ops">'
        '<div class="cx-ops-chip">THREAT OPERATIONS</div>'
        f'<div class="cx-metrics">{cards}</div>'
        "</div>"
    )


def render_security_overview(metrics):
    counts = metrics["severity_counts"]
    open_count = len(metrics["open_alerts"])
    cards = "".join(
        [
            kpi_card(
                "TOTAL EVENTS",
                fmt_count(len(metrics["events"])),
                f"{fmt_count(len(metrics['processes']))} process telemetry",
            ),
            kpi_card(
                "SECURITY DETECTIONS",
                fmt_count(len(metrics["detections"])),
                f"avg risk {metrics['avg_risk']:g} \u00b7 peak {metrics['max_risk']:g}",
                "#22d3ee",
            ),
            kpi_card(
                "OPEN ALERTS",
                fmt_count(open_count),
                f"{fmt_count(len(metrics['alerts']) - open_count)} resolved",
                "#ff9f45" if open_count else ACCENT,
            ),
            kpi_card(
                "CRITICAL / HIGH",
                f"{counts['critical']} / {counts['high']}",
                f"from {metrics['severity_source']}",
                "#ff4d6d" if counts["critical"] else "#ff9f45",
            ),
        ]
    )
    render_html('<div class="cx-section">SECURITY OVERVIEW</div>')
    render_html(f'<div class="cx-kpis">{cards}</div>')


def render_threat_activity(metrics):
    events = metrics["events"]
    if not events:
        panel(
            "THREAT ACTIVITY",
            empty_state("No telemetry yet", "Run the CIPHER-X agent, then refresh."),
            "📈",
        )
        return
    signals = metrics["detections"] + metrics["alerts"] + metrics["correlations"]
    series, interval = bucket_series(events, signals)
    if not series:
        panel(
            "THREAT ACTIVITY",
            empty_state("No usable timestamps", "Events are present but carry no parseable time."),
            "📈",
        )
        return
    body = chart_legend([("ALL EVENTS", ACCENT), ("DETECTIONS & ALERTS", "#ff9f45")])
    body += timeseries_svg(series, "main")
    span = f"{fmt_day(metrics['earliest'])} \u2192 {fmt_day(metrics['latest'])}"
    panel("THREAT ACTIVITY", body, "📈", f"{interval} \u00b7 {span}")


def render_alert_severity(metrics):
    counts = metrics["severity_counts"]
    total = sum(counts.values())
    if not total:
        panel(
            "ALERT SEVERITY",
            empty_state("No severities recorded", "No alerts or detections carry a severity field."),
            "🛡",
        )
        return
    shown = ["critical", "high", "medium", "low"]
    shown += [name for name in ("info", "unknown") if counts[name]]
    peak = max(counts.values()) or 1
    body = "".join(
        bar_row(name.upper(), counts[name], peak, severity_color(name)) for name in shown
    )
    panel("ALERT SEVERITY", body, "🛡", f"from {metrics['severity_source']}")


def render_event_types(metrics):
    types = metrics["event_types"]
    if not types:
        panel("EVENT TYPES", empty_state("No events loaded", "The log is empty."), "▦")
        return
    peak = max(types.values())
    body = "".join(
        bar_row(type_label(name), count, peak, ACCENT if name in PROCESS_TYPES else ACCENT_SOFT)
        for name, count in types.most_common(EVENT_TYPE_LIMIT)
    )
    panel("EVENT TYPES", body, "▦", f"{len(types)} distinct types")


def render_detection_intelligence(metrics):
    rows = metrics["rows"]
    if not rows:
        panel(
            "DETECTION INTELLIGENCE",
            empty_state("No detections recorded", "The engine has not fired a rule yet."),
            "◈",
        )
        return

    rules = Counter(row["rule"] for row in rows)
    peak = max(rules.values())
    body = '<div class="cx-side-label">TOP DETECTION RULES</div>'
    body += "".join(
        bar_row(
            rule,
            count,
            peak,
            severity_color(worst_severity(r["severity"] for r in rows if r["rule"] == rule)),
        )
        for rule, count in rules.most_common(TOP_RULES_LIMIT)
    )

    mitre = Counter(
        (row["mitre_id"], row["mitre_name"]) for row in rows if row["mitre_id"]
    )
    body += '<div class="cx-side-label" style="margin-top:16px">MITRE ATT&amp;CK TECHNIQUES</div>'
    if mitre:
        mitre_rows = [
            [
                f'<span class="mono" style="color:{ACCENT}">{esc(identifier)}</span>',
                esc(name or "\u2014", 46),
                badge(
                    worst_severity(
                        r["severity"] for r in rows if r["mitre_id"] == identifier
                    )
                ),
                fmt_count(count),
            ]
            for (identifier, name), count in mitre.most_common(TOP_MITRE_LIMIT)
        ]
        body += table(["TECHNIQUE", "NAME", "SEVERITY", "HITS"], mitre_rows)
    else:
        body += empty_state(
            "No ATT&CK mappings", "Detections in this log carry no mitre_technique_id."
        )

    risks = [row["risk"] for row in rows if row["risk"]]
    body += (
        '<div class="cx-bar-row" style="margin-top:14px;grid-template-columns:1fr 1fr 1fr">'
        f'<div class="cx-bar-label">AVG RISK <b style="color:#eaf6ff">{metrics["avg_risk"]:g}</b></div>'
        f'<div class="cx-bar-label">PEAK RISK <b style="color:#eaf6ff">{metrics["max_risk"]:g}</b></div>'
        f'<div class="cx-bar-label">SCORED HITS <b style="color:#eaf6ff">{fmt_count(len(risks))}</b></div>'
        "</div>"
    )
    panel("DETECTION INTELLIGENCE", body, "◈", f"{fmt_count(len(rows))} rule hits")


def security_events(metrics):
    """Everything except plain process telemetry, newest first."""
    interesting = (
        metrics["detections"] + metrics["alerts"] + metrics["correlations"] + metrics["file_events"]
    )
    return sorted(interesting, key=lambda event: (event["ts"] or EPOCH, event["seq"]), reverse=True)


def render_recent_events(metrics, limit=RECENT_EVENTS_LIMIT):
    ordered = security_events(metrics)
    if not ordered:
        fallback = list(reversed(metrics["processes"]))[:limit]
        if not fallback:
            panel(
                "RECENT SECURITY EVENTS",
                empty_state("No events recorded", "Start the agent to populate the log."),
                "🕑",
            )
            return
        rows = [
            [
                f'<span class="mono">{escape(fmt_clock(event["ts"]))}</span>',
                escape(type_label(event["event_type"])),
                esc(event["process"] or "\u2014", 34),
                esc(event["username"] or "\u2014", 24),
                f'<span class="mono">{event["pid"] if event["pid"] is not None else DASH}</span>',
            ]
            for event in fallback
        ]
        panel(
            "RECENT SECURITY EVENTS",
            '<div class="cx-side-label">No detections yet \u2014 showing latest process telemetry</div>'
            + table(["TIME", "EVENT", "PROCESS", "USER", "PID"], rows),
            "🕑",
        )
        return

    rows = []
    for event in ordered[:limit]:
        det = primary_detection(event)
        rows.append(
            [
                f'<span class="mono">{escape(fmt_clock(event["ts"]))}</span>',
                escape(type_label(event["event_type"])),
                esc(event["process"] or event["file_path"] or "\u2014", 30),
                esc(event["username"] or "\u2014", 22),
                esc(det["rule"] or "\u2014", 34),
                badge(det["severity"]),
                risk_cell(det["risk"] or event["risk"]),
                f'<span class="mono" title="{esc(det["mitre_name"])}">'
                f'{esc(det["mitre_id"] or DASH)}</span>',
            ]
        )
    panel(
        "RECENT SECURITY EVENTS",
        table(["TIME", "EVENT", "PROCESS", "USER", "RULE", "SEVERITY", "RISK", "MITRE"], rows),
        "🕑",
        f"newest {min(limit, len(ordered))} of {fmt_count(len(ordered))}",
    )


def render_footer(metrics):
    render_html(
        '<div class="cx-foot">'
        f"{APP_NAME} {APP_VERSION} &nbsp;|&nbsp; {fmt_count(len(metrics['events']))} EVENTS"
        f" &nbsp;|&nbsp; {fmt_count(len(metrics['detections']))} DETECTIONS"
        f" &nbsp;|&nbsp; {fmt_count(len(metrics['alerts']))} ALERTS"
        f" &nbsp;|&nbsp; AVG RISK {metrics['avg_risk']:g}"
        "</div>"
    )


# --------------------------------------------------------------------------
# Investigation helpers
# --------------------------------------------------------------------------


def related_events(
    event,
    events,
    window_seconds=CORRELATION_WINDOW_SECONDS,
    limit=RELATED_EVENTS_LIMIT,
):
    """Events near the alert in time that share its PID or process name."""
    if not event["ts"]:
        return []
    window = timedelta(seconds=window_seconds)
    found = []
    for candidate in events:
        if candidate is event or not candidate["ts"]:
            continue
        if abs(candidate["ts"] - event["ts"]) > window:
            continue
        same_pid = event["pid"] is not None and candidate["pid"] == event["pid"]
        same_proc = bool(event["process"]) and candidate["process"] == event["process"]
        if same_pid or same_proc:
            found.append(candidate)
    found.sort(key=lambda item: item["ts"], reverse=True)
    return found[:limit]


def alert_label(event):
    stamp = fmt_stamp(event["ts"])
    title = event["title"] or primary_detection(event)["rule"] or type_label(event["event_type"])
    identifier = event["alert_id"] or f"seq-{event['seq']}"
    return f"[{event['severity'].upper()}] {stamp} \u00b7 {title} \u00b7 {identifier}"


def render_investigation(event, events):
    det = primary_detection(event)
    fields = [
        kv("PROCESS", event["process"] or DASH),
        kv("PARENT PROCESS", event["parent"] or DASH),
        kv("PID", event["pid"] if event["pid"] is not None else DASH, mono=True),
        kv("PARENT PID", event["ppid"] if event["ppid"] is not None else DASH, mono=True),
        kv("USERNAME", event["username"] or DASH),
        kv("DETECTION RULE", det["rule"] or DASH),
        kv("MITRE TECHNIQUE", f"{det['mitre_id']} {det['mitre_name']}".strip() or DASH),
        kv("RISK SCORE", f"{to_float(det['risk'] or event['risk']):g}"),
        kv("SEVERITY", event["severity"].upper()),
        kv("STATUS", (event["status"] or "open").upper()),
    ]
    if event["executable"]:
        fields.append(kv("EXECUTABLE", event["executable"], mono=True, full_width=True))
    if event["file_path"]:
        fields.append(kv("FILE", event["file_path"], mono=True, full_width=True))
    fields.append(
        kv("COMMAND LINE", event["command_line"] or DASH, mono=True, full_width=True)
    )
    if event["description"]:
        fields.append(
            kv("DESCRIPTION", event["description"], mono=True, full_width=True)
        )

    body = kv_grid(fields)

    linked = related_events(event, events)
    body += '<div class="cx-side-label" style="margin-top:16px">RELATED EVENTS</div>'
    if linked:
        body += table(
            ["TIME", "EVENT", "PROCESS", "PID", "RULE", "SEVERITY"],
            [
                [
                    f'<span class="mono">{escape(fmt_clock(item["ts"]))}</span>',
                    escape(type_label(item["event_type"])),
                    esc(item["process"] or DASH, 28),
                    f'<span class="mono">{item["pid"] if item["pid"] is not None else DASH}</span>',
                    esc(primary_detection(item)["rule"] or DASH, 30),
                    badge(item["severity"]),
                ]
                for item in linked
            ],
        )
    else:
        body += empty_state(
            "No linked telemetry",
            "Nothing else in the log shares this PID or process within two minutes.",
        )

    title = event["title"] or det["rule"] or "SECURITY ALERT"
    panel(
        "INVESTIGATION",
        body,
        "🔎",
        f"{event['alert_id'] or 'no alert id'} \u00b7 {fmt_stamp(event['ts'])}",
    )
    return title


def alert_card(event, selected=False):
    det = primary_detection(event)
    color = severity_color(event["severity"])
    return (
        f'<div class="cx-alert{" sel" if selected else ""}" style="border-left-color:{color}">'
        '<div class="cx-alert-top">'
        f"{badge(event['severity'])}"
        f'<span class="cx-alert-id">{esc(event["alert_id"] or type_label(event["event_type"]))}</span>'
        "</div>"
        f'<div class="cx-alert-title">{esc(event["title"] or det["rule"] or "Security alert", 90)}</div>'
        f'<div class="cx-alert-meta">{escape(fmt_stamp(event["ts"]))} &nbsp;\u00b7&nbsp; '
        f'RISK {to_float(event["risk"] or det["risk"]):g} &nbsp;\u00b7&nbsp; '
        f'{escape((event["status"] or "open").upper())}</div>'
        "</div>"
    )


# --------------------------------------------------------------------------
# Views
# --------------------------------------------------------------------------


def view_overview(metrics):
    render_threat_operations(metrics)
    render_security_overview(metrics)

    left, right = st.columns([1.55, 1], gap="medium")
    with left:
        render_threat_activity(metrics)
    with right:
        render_alert_severity(metrics)

    lower_left, lower_right = st.columns([1, 1.25], gap="medium")
    with lower_left:
        render_event_types(metrics)
    with lower_right:
        render_detection_intelligence(metrics)

    render_recent_events(metrics)


def view_alerts(metrics):
    alerts = sorted(
        metrics["alerts"] + metrics["correlations"],
        key=lambda event: (event["ts"] or EPOCH, event["seq"]),
        reverse=True,
    )
    render_html('<div class="cx-section">SECURITY ALERTS</div>')

    if not alerts:
        panel(
            "SECURITY ALERTS",
            empty_state(
                "No alerts raised",
                "The alerting engine has not written a security_alert or correlation_alert event.",
            ),
            "🚨",
        )
        return

    filter_left, filter_mid, filter_right = st.columns([1, 1, 1.4])
    severities = [name for name in SEVERITY_ORDER if any(a["severity"] == name for a in alerts)]
    with filter_left:
        chosen_sev = st.multiselect("Severity", severities, default=severities)
    statuses = sorted({(alert["status"] or "open") for alert in alerts})
    with filter_mid:
        chosen_status = st.multiselect("Status", statuses, default=statuses)
    with filter_right:
        query = st.text_input("Search title, rule or process", "")

    filtered = [
        alert
        for alert in alerts
        if alert["severity"] in chosen_sev
        and (alert["status"] or "open") in chosen_status
        and (
            not query
            or query.lower()
            in " ".join(
                [
                    alert["title"],
                    alert["process"],
                    alert["description"],
                    primary_detection(alert)["rule"],
                ]
            ).lower()
        )
    ]

    if not filtered:
        panel("SECURITY ALERTS", empty_state("No alerts match", "Widen the filters above."), "🚨")
        return

    choice = st.selectbox(
        "Select an alert to investigate",
        list(range(len(filtered))),
        format_func=lambda index: alert_label(filtered[index]),
    )
    selected = filtered[choice]

    queue, detail = st.columns([1, 1.5], gap="medium")
    with queue:
        window = (
            filtered[:ALERT_QUEUE_LIMIT]
            if choice < ALERT_QUEUE_LIMIT
            else filtered[choice : choice + ALERT_QUEUE_LIMIT]
        )
        cards = "".join(alert_card(alert, alert is selected) for alert in window)
        panel(
            "ALERT QUEUE",
            cards,
            "🚨",
            f"{fmt_count(len(filtered))} of {fmt_count(len(alerts))}",
        )
    with detail:
        render_investigation(selected, metrics["events"])


def view_detections(metrics):
    rows = metrics["rows"]
    render_html('<div class="cx-section">DETECTIONS</div>')
    if not rows:
        panel(
            "DETECTIONS",
            empty_state("No detections recorded", "No security_detection events in the log."),
            "◈",
        )
        return

    severities = [name for name in SEVERITY_ORDER if any(row["severity"] == name for row in rows)]
    rules = sorted({row["rule"] for row in rows})
    techniques = sorted({row["mitre_id"] for row in rows if row["mitre_id"]})

    col_a, col_b, col_c, col_d = st.columns([1, 1.3, 1, 1])
    with col_a:
        chosen_sev = st.multiselect("Severity", severities, default=severities)
    with col_b:
        chosen_rules = st.multiselect("Detection rule", rules, default=[])
    with col_c:
        chosen_mitre = st.multiselect("MITRE technique", techniques, default=[])
    with col_d:
        query = st.text_input("Search process or user", "")

    filtered = [
        row
        for row in rows
        if row["severity"] in chosen_sev
        and (not chosen_rules or row["rule"] in chosen_rules)
        and (not chosen_mitre or row["mitre_id"] in chosen_mitre)
        and (
            not query
            or query.lower() in f"{row['process']} {row['username']} {row['command_line']}".lower()
        )
    ]
    filtered.sort(key=lambda row: (row["ts"] or EPOCH), reverse=True)

    body = table(
        ["TIME", "RULE", "SEVERITY", "PROCESS", "PARENT", "PID", "USER", "RISK", "MITRE"],
        [
            [
                f'<span class="mono">{escape(fmt_stamp(row["ts"]))}</span>',
                esc(row["rule"], 38),
                badge(row["severity"]),
                esc(row["process"] or DASH, 26),
                esc(row["parent"] or DASH, 24),
                f'<span class="mono">{row["pid"] if row["pid"] is not None else DASH}</span>',
                esc(row["username"] or DASH, 22),
                risk_cell(row["risk"]),
                f'<span class="mono" title="{esc(row["mitre_name"])}">'
                f'{esc(row["mitre_id"] or DASH)}</span>',
            ]
            for row in filtered[:DETECTION_TABLE_LIMIT]
        ],
    )
    panel(
        "DETECTION RESULTS",
        body,
        "◈",
        f"{fmt_count(len(filtered))} of {fmt_count(len(rows))} rule hits",
    )

    if filtered:
        with st.expander("Open a detection in the investigation view"):
            index = st.selectbox(
                "Detection",
                list(range(min(len(filtered), DETECTION_TABLE_LIMIT))),
                format_func=lambda i: (
                    f"{fmt_stamp(filtered[i]['ts'])} \u00b7 {filtered[i]['rule']} \u00b7 "
                    f"{filtered[i]['process'] or 'unknown process'}"
                ),
                key="detection_pick",
            )
            render_investigation(filtered[index]["event"], metrics["events"])


def view_process_activity(metrics):
    processes = list(reversed(metrics["processes"]))
    render_html('<div class="cx-section">PROCESS ACTIVITY</div>')
    if not processes:
        panel(
            "PROCESS ACTIVITY",
            empty_state("No process telemetry", "No process_observed events in the log."),
            "⚙",
        )
        return

    users = sorted({event["username"] for event in processes if event["username"]})
    col_a, col_b, col_c = st.columns([1.4, 1, 1])
    with col_a:
        query = st.text_input("Search process, executable or command line", "")
    with col_b:
        chosen_users = st.multiselect("User", users, default=[])
    with col_c:
        limit = st.slider(
            "Rows",
            PROCESS_ROWS_MIN,
            PROCESS_ROWS_MAX,
            PROCESS_ROWS_DEFAULT,
            step=PROCESS_ROWS_STEP,
        )

    filtered = [
        event
        for event in processes
        if (not chosen_users or event["username"] in chosen_users)
        and (
            not query
            or query.lower()
            in f"{event['process']} {event['executable']} {event['command_line']}".lower()
        )
    ]

    series, interval = bucket_series(metrics["processes"])
    if series:
        panel(
            "PROCESS TIMELINE",
            timeseries_svg(series, "proc", ACCENT_SOFT),
            "⚙",
            f"{interval} \u00b7 {fmt_count(len(processes))} process events",
        )

    top = Counter(event["process"] for event in filtered if event["process"])
    table_column, top_column = st.columns([2, 1], gap="medium")
    with table_column:
        panel(
            "PROCESS EVENTS",
            table(
                ["TIME", "PROCESS", "PID", "PARENT PID", "USER", "EXECUTABLE"],
                [
                    [
                        f'<span class="mono">{escape(fmt_stamp(event["ts"]))}</span>',
                        esc(event["process"] or DASH, 30),
                        f'<span class="mono">{event["pid"] if event["pid"] is not None else DASH}</span>',
                        f'<span class="mono">{event["ppid"] if event["ppid"] is not None else DASH}</span>',
                        esc(event["username"] or DASH, 22),
                        f'<span class="mono" title="{esc(event["executable"] or event["command_line"])}">'
                        f'{esc(event["executable"] or event["command_line"] or DASH, 44)}</span>',
                    ]
                    for event in filtered[:limit]
                ],
            ),
            "⚙",
            f"{fmt_count(len(filtered))} of {fmt_count(len(processes))}",
        )
    with top_column:
        if top:
            peak = top.most_common(1)[0][1]
            panel(
                "MOST ACTIVE PROCESSES",
                "".join(bar_row(name, count, peak) for name, count in top.most_common(TOP_PROCESSES_LIMIT)),
                "⚙",
            )


def view_file_activity(metrics):
    files = sorted(
        metrics["file_events"],
        key=lambda event: (event["ts"] or EPOCH, event["seq"]),
        reverse=True,
    )
    render_html('<div class="cx-section">FILE ACTIVITY</div>')
    if not files:
        panel("FILE ACTIVITY", empty_state("No file activity recorded", ""), "🗂")
        return

    query = st.text_input("Search file path", "")
    filtered = [event for event in files if not query or query.lower() in event["file_path"].lower()]

    rows = []
    for event in filtered[:FILE_TABLE_LIMIT]:
        det = primary_detection(event)
        digest = as_text(event["file_hash"], 18) or DASH
        rows.append(
            [
                f'<span class="mono">{escape(fmt_stamp(event["ts"]))}</span>',
                escape(type_label(event["event_type"])),
                f'<span class="mono" title="{esc(event["file_path"])}">'
                f'{esc(event["file_path"] or DASH, 52)}</span>',
                esc(event["file_action"] or DASH, 18),
                esc(det["rule"] if event["detections"] else DASH, 30),
                badge(event["severity"]),
                f'<span class="mono" title="{esc(event["file_hash"])}">{esc(digest)}</span>',
            ]
        )
    panel(
        "FILE EVENTS",
        table(["TIME", "EVENT", "FILE", "ACTION", "DETECTION", "SEVERITY", "HASH"], rows),
        "🗂",
        f"{fmt_count(len(filtered))} of {fmt_count(len(files))}",
    )


def view_investigations(metrics):
    render_html('<div class="cx-section">INVESTIGATIONS</div>')
    cases = sorted(
        metrics["correlations"] or metrics["open_alerts"],
        key=lambda event: (to_float(event["risk"]), event["ts"] or EPOCH),
        reverse=True,
    )
    source = "correlation alerts" if metrics["correlations"] else "open security alerts"

    counts = metrics["severity_counts"]
    render_html(
        '<div class="cx-kpis">'
        + kpi_card("OPEN CASES", fmt_count(len(cases)), f"from {source}")
        + kpi_card(
            "CRITICAL",
            fmt_count(counts["critical"]),
            "requires immediate response",
            "#ff4d6d",
        )
        + kpi_card("HIGH", fmt_count(counts["high"]), "triage next", "#ff9f45")
        + kpi_card(
            "ENDPOINTS",
            fmt_count(metrics["machines"]),
            metrics["endpoint"],
            ACCENT_SOFT,
        )
        + "</div>"
    )

    if not cases:
        panel(
            "CASE QUEUE",
            empty_state(
                "No open investigations",
                "Nothing is correlated or unresolved in the current log.",
            ),
            "🔍",
        )
        return

    for position, case in enumerate(cases[:CASE_LIMIT]):
        det = primary_detection(case)
        title = case["title"] or det["rule"] or type_label(case["event_type"])
        header = (
            f"{case['severity'].upper()}  \u00b7  {title}  \u00b7  "
            f"risk {to_float(case['risk'] or det['risk']):g}  \u00b7  {fmt_stamp(case['ts'])}"
        )
        with st.expander(header, expanded=(position == 0)):
            render_investigation(case, metrics["events"])


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------

# Name, sidebar icon and handler for every page, defined once. The sidebar
# navigation and the dispatcher both read this table.
PAGES = (
    Page("OVERVIEW", "▣", view_overview),
    Page("ALERTS", "🚨", view_alerts),
    Page("DETECTIONS", "◈", view_detections),
    Page("PROCESS ACTIVITY", "⚙", view_process_activity),
    Page("FILE ACTIVITY", "🗂", view_file_activity),
    Page("INVESTIGATIONS", "🔍", view_investigations),
)


def render_log_notice(events_path, events):
    if not events_path.exists():
        panel(
            "TELEMETRY LOG NOT FOUND",
            empty_state(
                "CIPHER-X cannot find the event log",
                f"Looked for {events_path}. Start the agent, or point "
                "CIPHER_X_EVENTS at the log.",
            ),
            "⚠",
        )
        return True
    if not events:
        panel(
            "WAITING FOR TELEMETRY",
            empty_state(
                "The event log is empty",
                "Run the CIPHER-X agent to collect events, then refresh.",
            ),
            "⚠",
        )
        return True
    return False


def main():
    st.markdown(CSS, unsafe_allow_html=True)

    if "page" not in st.session_state:
        st.session_state.page = PAGES[0].name

    events_path = resolve_events_file()
    mtime, size = file_signature(events_path)
    events, malformed = load_events(str(events_path), mtime, size)
    metrics = get_metrics(events)

    render_sidebar(metrics, events_path, malformed)
    render_header(metrics)

    if render_log_notice(events_path, events):
        return

    handler = next(
        (page.handler for page in PAGES if page.name == st.session_state.page),
        PAGES[0].handler,
    )
    handler(metrics)
    render_footer(metrics)


if __name__ == "__main__":
    main()