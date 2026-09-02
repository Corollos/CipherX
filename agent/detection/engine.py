"""
CIPHER-X Detection Engine

Analyzes process behavior and identifies potentially
suspicious execution patterns.
"""

from agent.detection.mitre import get_mitre_mapping

SUSPICIOUS_PARENT_CHILD = {
    ("powershell.exe", "cmd.exe"),
    ("cmd.exe", "powershell.exe"),
    ("wscript.exe", "powershell.exe"),
    ("cscript.exe", "powershell.exe"),
}

SUSPICIOUS_COMMAND_PATTERNS = {
    "powershell": [
        "-encodedcommand",
        "-enc",
        "invoke-expression",
        "iex ",
        "downloadstring",
        "downloadfile",
    ],
    "cmd": [
        "/c powershell",
        "/c certutil",
    ],
    "mshta": [
        "javascript:",
        "vbscript:",
        "http://",
        "https://",
    ],
    "rundll32": [
        "javascript:",
        "http://",
        "https://",
    ],
    "regsvr32": [
        "http://",
        "https://",
        "/s",
    ],
    "certutil": [
        "-urlcache",
        "-decode",
        "-decodehex",
        "http://",
        "https://",
    ],
    "wscript": [
        "http://",
        "https://",
        ".vbs",
        ".vbe",
    ],
    "cscript": [
        "http://",
        "https://",
        ".vbs",
        ".vbe",
    ],
}


def add_mitre_context(detection, rule):
    """
    Add MITRE ATT&CK context to a detection.
    """

    mitre = get_mitre_mapping(rule)

    if mitre:
        detection["mitre_technique_id"] = (
            mitre["technique_id"]
        )
        detection["mitre_technique_name"] = (
            mitre["technique_name"]
        )

    return detection


def get_command_category(child_name):
    """
    Determine which command-line detection category
    applies to the child process.
    """

    child = (child_name or "").lower()

    if "powershell" in child:
        return "powershell"

    if "cmd" in child:
        return "cmd"

    if "mshta" in child:
        return "mshta"

    if "rundll32" in child:
        return "rundll32"

    if "regsvr32" in child:
        return "regsvr32"

    if "certutil" in child:
        return "certutil"

    if "wscript" in child:
        return "wscript"

    if "cscript" in child:
        return "cscript"

    return None


def get_mitre_rule(child_name, command):
    """
    Select the most specific MITRE ATT&CK mapping
    for the detected process behavior.
    """

    child = (child_name or "").lower()

    if "powershell" in child:
        return "powershell_execution"

    if "cmd" in child:
        return "cmd_execution"

    if "wscript" in child or "cscript" in child:
        return "visual_basic_execution"

    if "mshta" in child:
        return "mshta_execution"

    if "rundll32" in child:
        return "rundll32_execution"

    if "regsvr32" in child:
        return "regsvr32_execution"

    if "certutil" in child:

        if (
            "urlcache" in command
            or "http://" in command
            or "https://" in command
        ):
            return "certutil_download"

        if (
            "-decode" in command
            or "-decodehex" in command
        ):
            return "certutil_decode"

    return "suspicious_command_line"


def find_command_matches(patterns, command):
    """
    Find suspicious command-line patterns while
    removing overlapping or duplicate matches.

    More specific patterns are preferred over
    shorter patterns contained within them.
    """

    matches = []

    # Check longer patterns first so, for example,
    # '-encodedcommand' takes priority over '-enc'.
    sorted_patterns = sorted(
        patterns,
        key=len,
        reverse=True,
    )

    for pattern in sorted_patterns:

        if pattern not in command:
            continue

        # Skip a pattern if it is already represented
        # by a more specific match.
        if any(
            pattern in existing_pattern
            for existing_pattern in matches
        ):
            continue

        matches.append(pattern)

    return matches


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

    if isinstance(command_line, list):
        command = " ".join(command_line).lower()
    else:
        command = str(command_line or "").lower()

    # -------------------------------------------------
    # Parent-child behavioral detection
    # -------------------------------------------------

    if (parent, child) in SUSPICIOUS_PARENT_CHILD:

        detection = {
            "rule": "suspicious_parent_child",
            "severity": "medium",
            "parent_process": parent_name,
            "child_process": child_name,
            "description": (
                f"Potentially suspicious process relationship: "
                f"{parent_name} spawned {child_name}."
            ),
        }

        detection = add_mitre_context(
            detection,
            "suspicious_parent_child",
        )

        detections.append(detection)

    # -------------------------------------------------
    # Command-line behavioral detection
    # -------------------------------------------------

    command_category = get_command_category(
        child_name
    )

    if command_category:

        patterns = SUSPICIOUS_COMMAND_PATTERNS[
            command_category
        ]

        matches = find_command_matches(
            patterns,
            command,
        )

        mitre_rule = get_mitre_rule(
            child_name,
            command,
        )

        for pattern in matches:

            detection = {
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

            detection = add_mitre_context(
                detection,
                mitre_rule,
            )

            detections.append(detection)

    return detections