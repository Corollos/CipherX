"""
CIPHER-X Continuous File Integrity Monitor

Continuously monitors a directory for file creation,
modification, and deletion using SHA-256 hashes.
"""

import time

from agent.event_logger.logger import log_event
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

                print("🚨 FILE INTEGRITY EVENT")
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

                # Add a standardized event type so file
                # activity can be identified in the central
                # CIPHER-X event log.
                change["event_type"] = "file_integrity_event"

                # Persist the file integrity event alongside
                # process and security detection events.
                log_event(change)

                print()

            # Update the baseline after processing changes
            # so the same event is not reported repeatedly.
            baseline = create_baseline(directory_path)

            time.sleep(interval)

    except KeyboardInterrupt:
        print("\nCIPHER-X file integrity monitor stopped.")


if __name__ == "__main__":
    monitor_directory("data/fim_test")