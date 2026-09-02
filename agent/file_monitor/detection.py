"""
CIPHER-X File Activity Detection Engine

Analyzes file integrity events and identifies potentially
suspicious file activity.
"""

from pathlib import Path


SUSPICIOUS_EXTENSIONS = {
    ".exe",
    ".dll",
    ".ps1",
    ".bat",
    ".cmd",
    ".vbs",
    ".vbe",
    ".js",
    ".jse",
}


SUSPICIOUS_PATH_KEYWORDS = {
    "appdata\\local\\temp",
    "\\temp\\",
    "\\startup\\",
}


def analyze_file_change(change):
    """
    Analyze a file integrity change for potentially
    suspicious characteristics.

    Args:
        change: File integrity event dictionary.

    Returns:
        List of detection dictionaries.
    """

    detections = []

    file_path = change.get("file_path", "")
    change_type = change.get("change_type", "")

    # Normalize the path for case-insensitive analysis.
    normalized_path = file_path.lower()

    # Extract the file extension.
    extension = Path(file_path).suffix.lower()

    # ---------------------------------------------------------
    # Suspicious file extension detection
    # ---------------------------------------------------------

    if extension in SUSPICIOUS_EXTENSIONS:

        detection = {
            "rule": "suspicious_file_extension",
            "severity": "high",
            "file_path": file_path,
            "change_type": change_type,
            "description": (
                f"Potentially suspicious file type detected: "
                f"'{extension}'."
            ),
        }

        detections.append(detection)

    # ---------------------------------------------------------
    # Suspicious file location detection
    # ---------------------------------------------------------

    for keyword in SUSPICIOUS_PATH_KEYWORDS:

        if keyword in normalized_path:

            detection = {
                "rule": "suspicious_file_location",
                "severity": "medium",
                "file_path": file_path,
                "change_type": change_type,
                "description": (
                    f"File activity detected in a potentially "
                    f"suspicious location: '{keyword}'."
                ),
            }

            detections.append(detection)

            break

    return detections