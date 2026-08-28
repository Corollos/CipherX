"""
CIPHER-X Security Event Model

Defines the standardized format used by CIPHER-X
to represent endpoint security telemetry.
"""

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import json


@dataclass
class ProcessEvent:
    """Represents a process-related security event."""

    event_type: str
    timestamp: str
    pid: int
    parent_pid: int | None
    process_name: str | None
    executable: str | None
    username: str | None

    def to_dict(self):
        """Convert the event into a dictionary."""

        return asdict(self)

    def to_json(self):
        """Convert the event into JSON."""

        return json.dumps(self.to_dict())


def create_process_event(process):
    """Create a standardized CIPHER-X event from process telemetry."""

    return ProcessEvent(
        event_type="process_observed",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pid=process["pid"],
        parent_pid=process["parent_pid"],
        process_name=process["name"],
        executable=process["executable"],
        username=process["username"],
    )