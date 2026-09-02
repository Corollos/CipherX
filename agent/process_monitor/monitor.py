"""
CIPHER-X Continuous Process Monitor
"""

from datetime import datetime, timezone
import time

import psutil

from agent.detection.correlation_manager import correlation_engine
from agent.detection.engine import analyze_process
from agent.detection.risk import calculate_risk_score, get_risk_level
from agent.event_collector.event import create_process_event
from agent.event_logger.logger import log_event
from agent.process_monitor.process_tree import collect_process_tree


def get_running_processes():
    """Return a snapshot of currently running processes."""

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
    """Continuously monitor for newly observed processes."""

    known_processes = get_running_processes()

    print("CIPHER-X continuous process monitor started.")
    print(f"Monitoring {len(known_processes)} existing processes.\n")

    try:
        while True:
            current_processes = get_running_processes()

            new_pids = (
                set(current_processes)
                - set(known_processes)
            )

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
                log_event(event)

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

                    detections = analyze_process(
                        parent["name"],
                        process.get("name"),
                        process.get("cmdline"),
                    )

                    if detections:
                        print("\nCIPHER-X DETECTION")

                        for detection in detections:
                            print(
                                f"Rule: "
                                f"{detection['rule']}"
                            )
                            print(
                                f"Severity: "
                                f"{detection['severity']}"
                            )
                            print(
                                f"Description: "
                                f"{detection['description']}"
                            )

                        risk_score = calculate_risk_score(
                            detections
                        )
                        risk_level = get_risk_level(
                            risk_score
                        )

                        print(
                            f"Risk Score: {risk_score}"
                        )
                        print(
                            f"Risk Level: "
                            f"{risk_level.upper()}"
                        )

                        detection_event = {
                            "event_type": "security_detection",
                            "timestamp": datetime.now(
                                timezone.utc
                            ).isoformat(),
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

                        for detection in detections:
                            correlation_event = {
                                **detection,
                                "timestamp": datetime.now(
                                    timezone.utc
                                ).isoformat(),
                                "pid": process.get("pid"),
                                "parent_pid": process.get("ppid"),
                                "process_name": process.get(
                                    "name"
                                ),
                                "username": process.get(
                                    "username"
                                ),
                            }

                            correlation_engine.add_event(
                                correlation_event
                            )

                        correlation_alerts = (
                            correlation_engine
                            .analyze_recent_events()
                        )

                        for alert in correlation_alerts:
                            alert["timestamp"] = datetime.now(
                                timezone.utc
                            ).isoformat()

                            print(
                                "\nCIPHER-X CORRELATION ALERT"
                            )
                            print(
                                f"Correlation Type: "
                                f"{alert.get('correlation_type')}"
                            )
                            print(
                                f"Severity: "
                                f"{alert.get('severity')}"
                            )
                            print(
                                f"Description: "
                                f"{alert.get('description')}"
                            )

                            if alert.get("rule"):
                                print(
                                    f"Rule: "
                                    f"{alert['rule']}"
                                )

                            if alert.get("related_rules"):
                                related_rules = ", ".join(
                                    alert["related_rules"]
                                )

                                print(
                                    f"Related Rules: "
                                    f"{related_rules}"
                                )

                            if alert.get(
                                "event_count"
                            ) is not None:
                                print(
                                    f"Event Count: "
                                    f"{alert['event_count']}"
                                )

                            log_event(alert)

                print()

            known_processes = current_processes

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nCIPHER-X monitor stopped.")


if __name__ == "__main__":
    monitor()