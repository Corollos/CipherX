"""
CIPHER-X Detection Engine

Analyzes process behavior and identifies potentially
suspicious execution patterns.
"""


SUSPICIOUS_PARENT_CHILD = {
    ("powershell.exe", "cmd.exe"),
    ("cmd.exe", "powershell.exe"),
    ("wscript.exe", "powershell.exe"),
    ("cscript.exe", "powershell.exe"),
}


SUSPICIOUS_COMMAND_PATTERNS = {
    "powershell": [
        "-encodedcommand",
        "invoke-expression",
        "iex ",
        "downloadstring",
        "downloadfile",
    ],
    "cmd": [
        "/c powershell",
        "/c certutil",
    ],
}


def analyze_process(parent_name, child_name, command_line=None):
    """
    Analyze a process relationship and command line
    for potentially suspicious behavior.

    Args:
        parent_name: Name of the parent process.
        child_name: Name of the child process.
        command_line: Process command line arguments.

    Returns:
        List of detection dictionaries.
    """

    detections = []

    parent = (parent_name or "").lower()
    child = (child_name or "").lower()

    # Normalize command-line arguments into one searchable string.
    if isinstance(command_line, list):
        command = " ".join(command_line).lower()
    else:
        command = str(command_line or "").lower()

    # ---------------------------------------------------------
    # Parent-child behavioral detection
    # ---------------------------------------------------------

    if (parent, child) in SUSPICIOUS_PARENT_CHILD:
        detections.append(
            {
                "rule": "suspicious_parent_child",
                "severity": "medium",
                "parent_process": parent_name,
                "child_process": child_name,
                "description": (
                    f"Potentially suspicious process relationship: "
                    f"{parent_name} spawned {child_name}."
                ),
            }
        )

    # ---------------------------------------------------------
    # Command-line behavioral detection
    # ---------------------------------------------------------

    patterns = []

    if "powershell" in child:
        patterns.extend(
            SUSPICIOUS_COMMAND_PATTERNS["powershell"]
        )

    if "cmd" in child:
        patterns.extend(
            SUSPICIOUS_COMMAND_PATTERNS["cmd"]
        )

    for pattern in patterns:
        if pattern in command:
            detections.append(
                {
                    "rule": "suspicious_command_line",
                    "severity": "high",
                    "parent_process": parent_name,
                    "child_process": child_name,
                    "command_line": command_line,
                    "description": (
                        f"Potentially suspicious command-line "
                        f"pattern detected: '{pattern}'."
                    ),
                }
            )

    return detections