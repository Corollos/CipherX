import json
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import streamlit as st


BASE_DIR = Path(__file__).resolve().parent.parent
EVENTS_FILE = BASE_DIR / "data" / "events.jsonl"


st.set_page_config(
    page_title="CIPHER-X",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


CSS = "\n".join([
    "<style>",
    "@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700&family=Inter:wght@400;500;600;700&display=swap');",

    "html, body, [class*='css'] {",
    "    font-family: 'Inter', sans-serif;",
    "}",

    ".stApp {",
    "    background: radial-gradient(circle at 50% 0%, #071a38 0%, #030912 45%, #02060c 100%);",
    "    color: #e8f4ff;",
    "}",

    ".block-container {",
    "    max-width: 1500px;",
    "    padding-top: 28px;",
    "    padding-bottom: 30px;",
    "}",

    "[data-testid='stSidebar'] {",
    "    background: #030914;",
    "    border-right: 1px solid #0b6cff;",
    "}",

    "[data-testid='stHeader'] {",
    "    background: transparent;",
    "}",

    "h1, h2, h3 {",
    "    font-family: 'Orbitron', sans-serif !important;",
    "}",

    ".top-header {",
    "    display: flex;",
    "    justify-content: space-between;",
    "    align-items: center;",
    "    padding: 8px 4px 24px 4px;",
    "}",

    ".brand {",
    "    display: flex;",
    "    align-items: center;",
    "    gap: 15px;",
    "}",

    ".shield {",
    "    font-size: 52px;",
    "    filter: drop-shadow(0 0 12px #008cff);",
    "}",

    ".brand-name {",
    "    font-family: 'Orbitron', sans-serif;",
    "    font-size: 32px;",
    "    font-weight: 700;",
    "    color: #f3f9ff;",
    "    letter-spacing: 2px;",
    "}",

    ".brand-name span {",
    "    color: #27a9ff;",
    "}",

    ".brand-subtitle {",
    "    color: #69bfff;",
    "    font-size: 15px;",
    "    margin-top: 3px;",
    "}",

    ".system-box {",
    "    display: flex;",
    "    align-items: center;",
    "    gap: 25px;",
    "    border: 1px solid #087cff;",
    "    border-radius: 12px;",
    "    padding: 13px 20px;",
    "    background: rgba(5, 24, 52, 0.75);",
    "    box-shadow: 0 0 20px rgba(0, 120, 255, 0.15);",
    "}",

    ".system-item {",
    "    padding-right: 24px;",
    "    border-right: 1px solid #19456f;",
    "}",

    ".system-item:last-child {",
    "    border-right: none;",
    "    padding-right: 0;",
    "}",

    ".system-label {",
    "    color: #7894ad;",
    "    font-size: 10px;",
    "    text-transform: uppercase;",
    "    letter-spacing: 1px;",
    "}",

    ".system-value {",
    "    color: #d9eeff;",
    "    font-size: 13px;",
    "    margin-top: 4px;",
    "}",

    ".online-dot {",
    "    color: #19e6b3;",
    "    text-shadow: 0 0 8px #19e6b3;",
    "}",

    ".malops-container {",
    "    position: relative;",
    "    border: 1px solid #087cff;",
    "    border-radius: 15px;",
    "    padding: 62px 25px 30px 25px;",
    "    background: linear-gradient(180deg, rgba(4, 25, 52, 0.95), rgba(2, 13, 29, 0.96));",
    "    box-shadow: 0 0 28px rgba(0, 108, 255, 0.16), inset 0 0 40px rgba(0, 108, 255, 0.04);",
    "    margin-bottom: 24px;",
    "}",

    ".malops-title {",
    "    position: absolute;",
    "    top: -17px;",
    "    left: 50%;",
    "    transform: translateX(-50%);",
    "    min-width: 340px;",
    "    text-align: center;",
    "    padding: 8px 55px;",
    "    background: linear-gradient(90deg, #087cff, #18bfff, #087cff);",
    "    color: white;",
    "    font-family: 'Orbitron', sans-serif;",
    "    font-size: 19px;",
    "    font-weight: 700;",
    "    letter-spacing: 2px;",
    "    border: 1px solid #48c9ff;",
    "    border-radius: 30px;",
    "    box-shadow: 0 0 18px rgba(0, 160, 255, 0.45);",
    "}",

    ".stat-card {",
    "    position: relative;",
    "    text-align: center;",
    "    border: 1px solid #3c759d;",
    "    border-radius: 8px;",
    "    padding: 28px 10px 18px 10px;",
    "    min-height: 140px;",
    "    background: rgba(3, 19, 39, 0.75);",
    "}",

    ".stat-icon {",
    "    position: absolute;",
    "    top: -28px;",
    "    left: 50%;",
    "    transform: translateX(-50%);",
    "    width: 58px;",
    "    height: 58px;",
    "    border-radius: 50%;",
    "    display: flex;",
    "    justify-content: center;",
    "    align-items: center;",
    "    background: #041a35;",
    "    border: 2px solid #0a9dff;",
    "    box-shadow: 0 0 16px rgba(0, 157, 255, 0.6);",
    "    font-size: 25px;",
    "}",

    ".stat-value {",
    "    font-family: 'Orbitron', sans-serif;",
    "    font-size: 35px;",
    "    font-weight: 700;",
    "    color: #f3fbff;",
    "    text-shadow: 0 0 12px rgba(42, 172, 255, 0.5);",
    "}",

    ".stat-label {",
    "    color: #c2e6ff;",
    "    font-size: 14px;",
    "    margin-top: 4px;",
    "}",

    ".panel {",
    "    border: 1px solid #096fbe;",
    "    border-radius: 13px;",
    "    background: linear-gradient(180deg, rgba(3, 23, 47, 0.95), rgba(2, 12, 26, 0.98));",
    "    box-shadow: 0 0 20px rgba(0, 100, 255, 0.10);",
    "    padding: 0 18px 18px 18px;",
    "    min-height: 390px;",
    "}",

    ".panel-title {",
    "    margin: 0 -18px 18px -18px;",
    "    padding: 11px 20px;",
    "    border-bottom: 1px solid #096fbe;",
    "    background: linear-gradient(90deg, rgba(7, 61, 112, 0.7), rgba(3, 26, 55, 0.2));",
    "    color: #dff5ff;",
    "    font-family: 'Orbitron', sans-serif;",
    "    font-size: 15px;",
    "    font-weight: 600;",
    "    letter-spacing: 1px;",
    "}",

    ".status-grid {",
    "    display: grid;",
    "    grid-template-columns: 1fr 1fr;",
    "    margin-top: 12px;",
    "}",

    ".status-item {",
    "    padding: 25px 10px;",
    "    text-align: center;",
    "    border-bottom: 1px solid #16496d;",
    "}",

    ".status-item:nth-child(odd) {",
    "    border-right: 1px solid #16496d;",
    "}",

    ".status-number {",
    "    color: #f2faff;",
    "    font-family: 'Orbitron', sans-serif;",
    "    font-size: 27px;",
    "    font-weight: 600;",
    "}",

    ".status-name {",
    "    color: #76a8c9;",
    "    font-size: 12px;",
    "    margin-top: 5px;",
    "}",

    ".footer-line {",
    "    text-align: center;",
    "    color: #507895;",
    "    font-size: 11px;",
    "    margin-top: 25px;",
    "    letter-spacing: 0.5px;",
    "}",

    ".stButton > button {",
    "    background: #061b35;",
    "    color: #62c5ff;",
    "    border: 1px solid #087cff;",
    "    border-radius: 7px;",
    "}",

    ".stButton > button:hover {",
    "    background: #0a2e55;",
    "    border-color: #36b7ff;",
    "    color: white;",
    "}",

    "</style>",
])


st.markdown(CSS, unsafe_allow_html=True)


def load_events():
    events = []

    if not EVENTS_FILE.exists():
        return events

    with EVENTS_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    return events


def format_time(timestamp):
    if not timestamp:
        return "N/A"

    try:
        value = datetime.fromisoformat(timestamp)

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone().strftime("%H:%M:%S")
    except ValueError:
        return timestamp


def format_date(timestamp):
    if not timestamp:
        return "N/A"

    try:
        value = datetime.fromisoformat(timestamp)

        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)

        return value.astimezone().strftime("%Y-%m-%d")
    except ValueError:
        return timestamp[:10]


def get_events_by_type(events, event_type):
    return [
        event
        for event in events
        if event.get("event_type") == event_type
    ]


def get_detection_rows(detections):
    rows = []

    for event in detections:
        for detection in event.get("detections", []):
            rows.append(
                {
                    "timestamp": event.get("timestamp", ""),
                    "rule": detection.get("rule", "unknown"),
                    "severity": detection.get("severity", "unknown"),
                    "mitre": detection.get(
                        "mitre_technique_id",
                        "N/A",
                    ),
                    "technique": detection.get(
                        "mitre_technique_name",
                        "Unknown",
                    ),
                    "process": event.get(
                        "process_name",
                        "Unknown",
                    ),
                    "pid": event.get("pid", ""),
                    "risk": event.get("risk_score", 0),
                }
            )

    return rows


events = load_events()

process_events = get_events_by_type(
    events,
    "process_observed",
)

detections = get_events_by_type(
    events,
    "security_detection",
)

alerts = get_events_by_type(
    events,
    "security_alert",
)

correlation_alerts = get_events_by_type(
    events,
    "correlation_alert",
)

file_events = [
    event
    for event in events
    if event.get("event_type") in [
        "file_integrity_event",
        "file_security_detection",
    ]
]


open_alerts = [
    alert
    for alert in alerts
    if str(
        alert.get("status", "")
    ).lower() == "open"
]


high_alerts = [
    alert
    for alert in alerts
    if str(
        alert.get("severity", "")
    ).lower() == "high"
]


critical_alerts = [
    alert
    for alert in alerts
    if str(
        alert.get("severity", "")
    ).lower() == "critical"
]


detection_rows = get_detection_rows(
    detections
)


if detection_rows:

    detection_df = pd.DataFrame(
        detection_rows
    )

else:

    detection_df = pd.DataFrame(
        columns=[
            "timestamp",
            "rule",
            "severity",
            "mitre",
            "technique",
            "process",
            "pid",
            "risk",
        ]
    )


latest_timestamp = ""

if events:
    latest_timestamp = events[-1].get(
        "timestamp",
        "",
    )


unique_users = set()

for event in events:

    username = event.get(
        "username"
    )

    if username:
        unique_users.add(username)


unique_machines = 1 if events else 0


recent_activity = len(
    events[-8:]
)


risk_values = [
    event.get("risk_score", 0)
    for event in detections
    if isinstance(
        event.get("risk_score"),
        (int, float),
    )
]


average_risk = (
    round(
        sum(risk_values) / len(risk_values),
        1,
    )
    if risk_values
    else 0
)


st.markdown(
    """
    <div class="top-header">
        <div class="brand">
            <div class="shield">🛡️</div>
            <div>
                <div class="brand-name">
                    CIPHER-<span>X</span>
                </div>
                <div class="brand-subtitle">
                    Endpoint Detection & Response
                </div>
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


endpoint_name = "LOCAL ENDPOINT"

if events:

    usernames = [
        event.get("username", "")
        for event in events
        if event.get("username")
    ]

    if usernames:
        endpoint_name = usernames[-1].split("\\")[0]


st.markdown(
    f"""
    <div class="system-box" style="position:absolute; right:30px; top:25px;">
        <div class="system-item">
            <div class="system-label">Endpoint</div>
            <div class="system-value">💻 {endpoint_name}</div>
        </div>
        <div class="system-item">
            <div class="system-label">Last Telemetry</div>
            <div class="system-value">{format_time(latest_timestamp)}</div>
        </div>
        <div class="system-item">
            <div class="system-label">Status</div>
            <div class="system-value">
                <span class="online-dot">●</span> ONLINE
            </div>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)


st.markdown(
    f"""
    <div class="malops-container">

        <div class="malops-title">
            THREAT OPERATIONS
        </div>

        <div style="display:grid; grid-template-columns:repeat(4,1fr); gap:18px;">

            <div class="stat-card">
                <div class="stat-icon">⚠</div>
                <div class="stat-value">{len(detections)}</div>
                <div class="stat-label">Active Malops</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">◷</div>
                <div class="stat-value">{recent_activity}</div>
                <div class="stat-label">Recent Activity</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">⌘</div>
                <div class="stat-value">{unique_machines}</div>
                <div class="stat-label">Affected Machines</div>
            </div>

            <div class="stat-card">
                <div class="stat-icon">♙</div>
                <div class="stat-value">{len(unique_users)}</div>
                <div class="stat-label">Affected Users</div>
            </div>

        </div>

    </div>
    """,
    unsafe_allow_html=True,
)


left, middle, right = st.columns(
    [1.2, 1, 1.2],
    gap="medium",
)


with left:

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">
                📈 &nbsp; ISSUES BY TIME
            </div>
        """,
        unsafe_allow_html=True,
    )

    if events:

        dates = [
            format_date(
                event.get("timestamp", "")
            )
            for event in events
        ]

        date_counts = (
            pd.Series(dates)
            .value_counts()
            .sort_index()
        )

        chart_df = pd.DataFrame(
            {
                "Events": date_counts
            }
        )

        st.line_chart(
            chart_df,
            height=270,
        )

    else:

        st.info(
            "No telemetry available."
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )


with middle:

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">
                🛡️ &nbsp; STATUS
            </div>

            <div class="status-grid">
        """,
        unsafe_allow_html=True,
    )

    scanning = len(process_events)

    reopened = sum(
        1
        for alert in alerts
        if str(
            alert.get("status", "")
        ).lower() == "reopened"
    )

    investigating = len(open_alerts)

    to_review = len(
        critical_alerts
    )

    st.markdown(
        f"""
        <div class="status-item">
            <div class="status-number">{scanning}</div>
            <div class="status-name">Scanning</div>
        </div>

        <div class="status-item">
            <div class="status-number">{reopened}</div>
            <div class="status-name">Reopened</div>
        </div>

        <div class="status-item">
            <div class="status-number">{investigating}</div>
            <div class="status-name">Under Investigation</div>
        </div>

        <div class="status-item">
            <div class="status-number">{to_review}</div>
            <div class="status-name">To Review</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        "</div></div>",
        unsafe_allow_html=True,
    )


with right:

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">
                ◈ &nbsp; DETECTION TYPE
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not detection_df.empty:

        rule_counts = (
            detection_df["rule"]
            .value_counts()
            .head(7)
            .sort_values()
        )

        type_df = pd.DataFrame(
            {
                "Detections": rule_counts
            }
        )

        st.bar_chart(
            type_df,
            height=290,
        )

    else:

        st.info(
            "No detections recorded."
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )


st.markdown(
    "<div style='height:20px'></div>",
    unsafe_allow_html=True,
)


overview_left, overview_right = st.columns(
    [1.3, 1],
    gap="medium",
)


with overview_left:

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">
                🎯 &nbsp; MITRE ATT&CK COVERAGE
            </div>
        """,
        unsafe_allow_html=True,
    )

    if not detection_df.empty:

        mitre_df = (
            detection_df[
                detection_df["mitre"] != "N/A"
            ]
            .groupby(
                ["mitre", "technique"]
            )
            .size()
            .reset_index(
                name="Detections"
            )
            .sort_values(
                "Detections",
                ascending=False,
            )
        )

        if not mitre_df.empty:

            for _, row in mitre_df.iterrows():

                st.markdown(
                    f"""
                    <div style="
                        display:flex;
                        justify-content:space-between;
                        align-items:center;
                        padding:10px 12px;
                        margin-bottom:7px;
                        background:#06182d;
                        border:1px solid #123d60;
                        border-radius:6px;
                    ">
                        <div>
                            <span style="
                                color:#27adff;
                                font-family:Orbitron;
                                font-weight:600;
                            ">
                                {row["mitre"]}
                            </span>
                            <span style="
                                color:#b7d8ed;
                                margin-left:12px;
                            ">
                                {row["technique"]}
                            </span>
                        </div>

                        <div style="
                            color:#63c8ff;
                            font-weight:700;
                        ">
                            {row["Detections"]}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

        else:

            st.info(
                "No MITRE mappings recorded."
            )

    else:

        st.info(
            "No detection data available."
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )


with overview_right:

    st.markdown(
        """
        <div class="panel">
            <div class="panel-title">
                🚨 &nbsp; ACTIVE ALERTS
            </div>
        """,
        unsafe_allow_html=True,
    )

    if alerts:

        for alert in reversed(
            alerts[-5:]
        ):

            severity_value = str(
                alert.get(
                    "severity",
                    "unknown",
                )
            ).upper()

            severity_color = {
                "CRITICAL": "#ff4d5a",
                "HIGH": "#ff8a45",
                "MEDIUM": "#ffd166",
                "LOW": "#27d69b",
            }.get(
                severity_value,
                "#63c8ff",
            )

            st.markdown(
                f"""
                <div style="
                    border-left:3px solid {severity_color};
                    background:#06182d;
                    border-top:1px solid #123d60;
                    border-right:1px solid #123d60;
                    border-bottom:1px solid #123d60;
                    border-radius:5px;
                    padding:10px 12px;
                    margin-bottom:8px;
                ">
                    <div style="
                        display:flex;
                        justify-content:space-between;
                    ">
                        <span style="
                            color:{severity_color};
                            font-weight:700;
                            font-size:11px;
                        ">
                            {severity_value}
                        </span>

                        <span style="
                            color:#547994;
                            font-size:10px;
                        ">
                            {alert.get("alert_id", "N/A")}
                        </span>
                    </div>

                    <div style="
                        color:#d9efff;
                        font-size:13px;
                        margin-top:5px;
                    ">
                        {alert.get("title", "Security Alert")}
                    </div>

                    <div style="
                        color:#638aa6;
                        font-size:10px;
                        margin-top:4px;
                    ">
                        Risk Score: {alert.get("risk_score", "N/A")}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

    else:

        st.success(
            "No active security alerts."
        )

    st.markdown(
        "</div>",
        unsafe_allow_html=True,
    )


st.markdown(
    f"""
    <div class="footer-line">
        CIPHER-X • Endpoint Telemetry &nbsp;|&nbsp;
        {len(events)} Events &nbsp;|&nbsp;
        {len(detections)} Detections &nbsp;|&nbsp;
        {len(alerts)} Alerts &nbsp;|&nbsp;
        Average Detection Risk: {average_risk}
    </div>
    """,
    unsafe_allow_html=True,
)


st.sidebar.markdown(
    "## 🛡️ CIPHER-X"
)

st.sidebar.markdown(
    "**Endpoint Detection & Response**"
)

st.sidebar.divider()

st.sidebar.write(
    f"Telemetry Events: {len(events)}"
)

st.sidebar.write(
    f"Security Detections: {len(detections)}"
)

st.sidebar.write(
    f"Security Alerts: {len(alerts)}"
)

st.sidebar.write(
    f"Correlation Alerts: {len(correlation_alerts)}"
)

st.sidebar.write(
    f"File Events: {len(file_events)}"
)

st.sidebar.divider()

if st.sidebar.button("↻ Refresh Dashboard"):
    st.rerun()

st.sidebar.caption(
    "CIPHER-X v1.0"
)