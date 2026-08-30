"""
CIPHER-X Continuous Process Monitor

Continuously monitors the Windows endpoint for newly
observed processes and generates standardized security events.
"""

import time

import psutil

from agent.detection.engine import analyze_process
from agent.detection.risk import calculate_risk_score, get_risk_level
from agent.event_collector.event import create_process_event
from agent.event_logger.logger import log_event
from agent.process_monitor.process_tree import collect_process_tree


def get_running_processes():
    """Return a snapshot of currently running process IDs."""

    processes = {}

    for process in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "cmdline"]
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

                event_data = {
                    "pid": process.get("pid"),
                    "parent_pid": process.get("ppid"),
                    "name": process.get("name"),
                    "executable": process.get("exe"),
                    "username": process.get("username"),
                    "command_line": process.get("cmdline"),
                }

                event = create_process_event(event_data)

                # Persist the process event for later investigation.
                log_event(event)

                # Build the current process tree so we can
                # understand the new process's parent relationship.
                process_tree = collect_process_tree()

                parent_pid = process.get("ppid")
                parent = process_tree.get(parent_pid)

                print("NEW PROCESS DETECTED")
                print(event.to_json())

                if parent:
                    print(
                        f"Parent Process: {parent['name']} "
                        f"(PID: {parent['pid']})"
                    )

                    # Analyze the parent-child relationship
                    # and command-line behavior using the
                    # CIPHER-X detection engine.
                    detections = analyze_process(
                        parent["name"],
                        process.get("name"),
                        process.get("cmdline"),
                    )

                    if detections:
                        print("\n🚨 CIPHER-X DETECTION")

                        for detection in detections:
                            print(
                                f"Rule: {detection['rule']}"
                            )
                            print(
                                f"Severity: {detection['severity']}"
                            )
                            print(
                                f"Description: "
                                f"{detection['description']}"
                            )

                        # Calculate the combined risk score
                        # for all detections associated with
                        # this process.
                        risk_score = calculate_risk_score(detections)
                        risk_level = get_risk_level(risk_score)

                        print(f"Risk Score: {risk_score}")
                        print(f"Risk Level: {risk_level.upper()}")

                        # Persist the security detection so it
                        # can be investigated after monitoring ends.
                        detection_event = {
                            "event_type": "security_detection",
                            "pid": process.get("pid"),
                            "parent_pid": process.get("ppid"),
                            "process_name": process.get("name"),
                            "parent_process": parent["name"],
                            "username": process.get("username"),
                            "command_line": process.get("cmdline"),
                            "detections": detections,
                            "risk_score": risk_score,
                            "risk_level": risk_level,
                        }

                        log_event(detection_event)

                print()

            known_processes = current_processes

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nCIPHER-X monitor stopped.")


if __name__ == "__main__":
    monitor()