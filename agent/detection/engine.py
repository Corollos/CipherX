"""
CIPHER-X Detection Engine

Analyzes process relationships and identifies
behavior that may warrant further investigation.
"""


SUSPICIOUS_PARENT_CHILD_RULES = {
    "powershell.exe": {
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    },
    "cmd.exe": {
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
    },
}


def normalize_process_name(name):
    """Normalize a process name for reliable comparisons."""

    if not name:
        return ""

    return name.lower().strip()


def detect_suspicious_parent_child(parent_name, child_name):
    """
    Check whether a parent-child process relationship
    matches one of our suspicious behavioral patterns.

    Returns a detection result dictionary or None.
    """

    parent = normalize_process_name(parent_name)
    child = normalize_process_name(child_name)

    suspicious_children = SUSPICIOUS_PARENT_CHILD_RULES.get(parent, set())

    if child in suspicious_children:
        return {
            "rule": "suspicious_parent_child",
            "severity": "medium",
            "parent_process": parent,
            "child_process": child,
            "description": (
                f"Potentially suspicious process relationship: "
                f"{parent} spawned {child}."
            ),
        }

    return None


def analyze_process(parent_name, child_name):
    """
    Analyze a process relationship and return any detections.
    """

    detection = detect_suspicious_parent_child(
        parent_name,
        child_name,
    )

    if detection:
        return [detection]

    return []