"""
CIPHER-X Security Event

Defines the standardized event structure used by CIPHER-X
to represent endpoint process activity.
"""

from datetime import datetime, timezone
import json


class ProcessEvent:
    """Represents a standardized process security event."""

    def __init__(
        self,
        event_type,
        timestamp,
        pid,
        parent_pid,
        process_name,
        executable,
        username,
        command_line=None,
    ):
        self.event_type = event_type
        self.timestamp = timestamp
        self.pid = pid
        self.parent_pid = parent_pid
        self.process_name = process_name
        self.executable = executable
        self.username = username
        self.command_line = command_line

    def to_dict(self):
        """Convert the event into a dictionary."""

        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "pid": self.pid,
            "parent_pid": self.parent_pid,
            "process_name": self.process_name,
            "executable": self.executable,
            "username": self.username,
            "command_line": self.command_line,
        }

    def to_json(self):
        """Convert the event into JSON."""

        return json.dumps(self.to_dict())


def create_process_event(process):
    """Create a standardized process event from process information."""

    return ProcessEvent(
        event_type="process_observed",
        timestamp=datetime.now(timezone.utc).isoformat(),
        pid=process.get("pid"),
        parent_pid=process.get("parent_pid"),
        process_name=process.get("name"),
        executable=process.get("executable"),
        username=process.get("username"),
        command_line=process.get("command_line"),
    )