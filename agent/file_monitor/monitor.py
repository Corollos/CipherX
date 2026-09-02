"""
CIPHER-X Continuous File Integrity Monitor

Continuously monitors a directory for file creation,
modification, and deletion using SHA-256 hashes and
analyzes file activity for suspicious behavior.
"""

import time

from agent.detection.risk import calculate_risk_score, get_risk_level
from agent.event_logger.logger import log_event
from agent.file_monitor.detection import analyze_file_change
from agent.file_monitor.integrity import (
    create_baseline,
    detect_changes,
)


def monitor_directory(directory_path, interval=5):
    """
    Continuously monitor a directory for file changes.

    Args:
        directory_path: Directory to monitor.
        interval: Number of seconds between scans.
    """

    baseline = create_baseline(directory_path)

    print("CIPHER-X file integrity monitor started.")
    print(f"Monitoring directory: {directory_path}")
    print(f"Baseline contains {len(baseline)} files.\n")

    try:
        while True:
            changes = detect_changes(
                directory_path,
                baseline,
            )

            for change in changes:
                print("FILE INTEGRITY EVENT")
                print(
                    f"Change Type: "
                    f"{change['change_type']}"
                )
                print(
                    f"File: "
                    f"{change['file_path']}"
                )

                if change["change_type"] == "file_modified":
                    print(
                        f"Previous Hash: "
                        f"{change['previous_hash']}"
                    )
                    print(
                        f"Current Hash: "
                        f"{change['current_hash']}"
                    )

                elif change["change_type"] == "file_created":
                    print(
                        f"Current Hash: "
                        f"{change['current_hash']}"
                    )

                elif change["change_type"] == "file_deleted":
                    print(
                        f"Previous Hash: "
                        f"{change['previous_hash']}"
                    )

                file_event = {
                    "event_type": "file_integrity_event",
                    **change,
                }

                log_event(file_event)

                detections = analyze_file_change(change)

                if detections:
                    print("\nCIPHER-X FILE DETECTION")

                    for detection in detections:
                        print(
                            f"Rule: {detection['rule']}"
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

                    print(f"Risk Score: {risk_score}")
                    print(
                        f"Risk Level: "
                        f"{risk_level.upper()}"
                    )

                    detection_event = {
                        "event_type": "file_security_detection",
                        "file_path": change["file_path"],
                        "change_type": change["change_type"],
                        "detections": detections,
                        "risk_score": risk_score,
                        "risk_level": risk_level,
                    }

                    log_event(detection_event)

                print()

            baseline = create_baseline(directory_path)

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nCIPHER-X file integrity monitor stopped.")


if __name__ == "__main__":
    monitor_directory("data/fim_test")