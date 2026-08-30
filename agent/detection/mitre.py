"""
CIPHER-X MITRE ATT&CK Mapping

Maps CIPHER-X detections to relevant MITRE ATT&CK
techniques and sub-techniques.
"""


MITRE_MAPPINGS = {
    "suspicious_parent_child": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },

    "suspicious_command_line": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },

    "powershell_execution": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
    },

    "cmd_execution": {
        "technique_id": "T1059.003",
        "technique_name": "Windows Command Shell",
    },

    "visual_basic_execution": {
        "technique_id": "T1059.005",
        "technique_name": "Visual Basic",
    },

    "mshta_execution": {
        "technique_id": "T1218.005",
        "technique_name": "System Binary Proxy Execution: Mshta",
    },

    "rundll32_execution": {
        "technique_id": "T1218.011",
        "technique_name": "System Binary Proxy Execution: Rundll32",
    },

    "regsvr32_execution": {
        "technique_id": "T1218.010",
        "technique_name": "System Binary Proxy Execution: Regsvr32",
    },

    "certutil_decode": {
        "technique_id": "T1140",
        "technique_name": "Deobfuscate/Decode Files or Information",
    },

    "certutil_download": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
    },
}


def get_mitre_mapping(rule):
    """
    Return MITRE ATT&CK information for a detection rule.

    Args:
        rule: CIPHER-X detection rule name.

    Returns:
        MITRE mapping dictionary or None.
    """

    return MITRE_MAPPINGS.get(rule)