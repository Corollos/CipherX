"""
CIPHER-X Event Logger

Persists security events so they can be reviewed
after the monitoring session has ended.
"""

import json
from pathlib import Path


LOG_FILE = Path("data/events.jsonl")


def log_event(event):
    """
    Append a security event to the CIPHER-X event log.

    Events are stored as JSON Lines (JSONL), with one
    event per line.
    """

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    with LOG_FILE.open("a", encoding="utf-8") as file:
        if hasattr(event, "to_dict"):
            data = event.to_dict()
        elif hasattr(event, "to_json"):
            data = json.loads(event.to_json())
        else:
            data = event

        file.write(json.dumps(data) + "\n")