"""
CIPHER-X MITRE ATT&CK Mapping

Maps CIPHER-X detection rules to relevant
MITRE ATT&CK techniques.
"""


MITRE_MAPPINGS = {
    "suspicious_command_line": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },

    "suspicious_parent_child": {
        "technique_id": "T1059",
        "technique_name": "Command and Scripting Interpreter",
    },
}


def get_mitre_mapping(rule):
    """
    Return the MITRE ATT&CK mapping for a detection rule.

    Args:
        rule: CIPHER-X detection rule name.

    Returns:
        MITRE mapping dictionary, or None if no mapping exists.
    """

    return MITRE_MAPPINGS.get(rule)