"""
CIPHER-X Continuous Process Monitor

Continuously monitors the Windows endpoint for newly
observed processes and generates standardized security events.
"""

import time

import psutil

from agent.event_collector.event import create_process_event


def get_running_processes():
    """Return a snapshot of currently running process IDs."""

    processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username"]
    ):
        try:
            processes[process.info["pid"]] = process.info

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return processes


def monitor(interval=2):
    """
    Continuously monitor for newly observed processes.

    Args:
        interval: Number of seconds between process snapshots.
    """

    known_processes = get_running_processes()

    print("CIPHER-X continuous process monitor started.")
    print(f"Monitoring {len(known_processes)} existing processes.\n")

    try:
        while True:
            current_processes = get_running_processes()

            new_pids = set(current_processes) - set(known_processes)

            for pid in new_pids:
                process = current_processes[pid]

                event = create_process_event(
                    {
                        "pid": process.get("pid"),
                        "parent_pid": process.get("ppid"),
                        "name": process.get("name"),
                        "executable": process.get("exe"),
                        "username": process.get("username"),
                    }
                )

                print("NEW PROCESS DETECTED")
                print(event.to_json())
                print()

            known_processes = current_processes

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nCIPHER-X monitor stopped.")


if __name__ == "__main__":
    monitor()