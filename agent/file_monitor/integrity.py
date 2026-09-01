"""
CIPHER-X File Integrity Monitor

Creates SHA-256 file hashes and detects changes
to monitored files.
"""

import hashlib
from pathlib import Path


def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.

    Args:
        file_path: Path to the file.

    Returns:
        SHA-256 hash string, or None if the file
        cannot be read.
    """

    try:
        sha256 = hashlib.sha256()

        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except (FileNotFoundError, PermissionError, OSError):
        return None


def create_baseline(directory_path):
    """
    Create a baseline of SHA-256 hashes for files
    in a directory.

    Args:
        directory_path: Directory to monitor.

    Returns:
        Dictionary mapping file paths to hashes.
    """

    baseline = {}

    directory = Path(directory_path)

    if not directory.exists():
        return baseline

    for file_path in directory.rglob("*"):

        if not file_path.is_file():
            continue

        file_hash = calculate_file_hash(file_path)

        if file_hash:
            baseline[str(file_path)] = file_hash

    return baseline


def detect_changes(directory_path, baseline):
    """
    Compare the current directory state against a
    previously created file hash baseline.

    Detects modified, new, and deleted files.
    """

    changes = []

    current_baseline = create_baseline(directory_path)

    for file_path, current_hash in current_baseline.items():

        if file_path not in baseline:

            changes.append({
                "change_type": "file_created",
                "file_path": file_path,
                "current_hash": current_hash,
            })

        elif baseline[file_path] != current_hash:

            changes.append({
                "change_type": "file_modified",
                "file_path": file_path,
                "previous_hash": baseline[file_path],
                "current_hash": current_hash,
            })

    for file_path, previous_hash in baseline.items():

        if file_path not in current_baseline:

            changes.append({
                "change_type": "file_deleted",
                "file_path": file_path,
                "previous_hash": previous_hash,
            })

    return changes