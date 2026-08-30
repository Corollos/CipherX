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
        "-enc",
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
        detection["mitre_technique_id"] = mitre["technique_id"]
        detection["mitre_technique_name"] = mitre["technique_name"]

    return detection


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

    # ---------------------------------------------------------
    # Determine command-line detection category
    # ---------------------------------------------------------

    command_category = None

    if "powershell" in child:
        command_category = "powershell"

    elif "cmd" in child:
        command_category = "cmd"

    elif "mshta" in child:
        command_category = "mshta"

    elif "rundll32" in child:
        command_category = "rundll32"

    elif "regsvr32" in child:
        command_category = "regsvr32"

    elif "certutil" in child:
        command_category = "certutil"

    elif "wscript" in child:
        command_category = "wscript"

    elif "cscript" in child:
        command_category = "cscript"

    # ---------------------------------------------------------
    # Command-line behavioral detection
    # ---------------------------------------------------------

    if command_category:

        patterns = SUSPICIOUS_COMMAND_PATTERNS[
            command_category
        ]

        for pattern in patterns:

            if pattern not in command:
                continue

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

            # -------------------------------------------------
            # Select the most specific MITRE ATT&CK mapping.
            # -------------------------------------------------

            mitre_rule = "suspicious_command_line"

            if "powershell" in child:
                mitre_rule = "powershell_execution"

            elif "cmd" in child:
                mitre_rule = "cmd_execution"

            elif "wscript" in child or "cscript" in child:
                mitre_rule = "visual_basic_execution"

            elif "mshta" in child:
                mitre_rule = "mshta_execution"

            elif "rundll32" in child:
                mitre_rule = "rundll32_execution"

            elif "regsvr32" in child:
                mitre_rule = "regsvr32_execution"

            elif "certutil" in child:

                if (
                    "urlcache" in command
                    or "http://" in command
                    or "https://" in command
                ):
                    mitre_rule = "certutil_download"

                elif (
                    "-decode" in command
                    or "-decodehex" in command
                ):
                    mitre_rule = "certutil_decode"

            detection = add_mitre_context(
                detection,
                mitre_rule,
            )

            detections.append(detection)

    return detections