"""
CIPHER-X Process Monitor

Collects process telemetry from the local Windows endpoint
and converts it into standardized CIPHER-X security events.
"""

import psutil

from agent.event_collector.event import create_process_event


def collect_processes():
    """Collect information about currently running processes."""

    processes = []

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            info = process.info

            processes.append(
                {
                    "pid": info.get("pid"),
                    "parent_pid": info.get("ppid"),
                    "name": info.get("name"),
                    "executable": info.get("exe"),
                    "username": info.get("username"),
                }
            )

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def collect_process_events():
    """Collect processes and convert them into CIPHER-X events."""

    events = []

    for process in collect_processes():
        event = create_process_event(process)
        events.append(event)

    return events


if __name__ == "__main__":
    events = collect_process_events()

    print(f"CIPHER-X generated {len(events)} process events.\n")

    for event in events[:10]:
        print(event.to_json())