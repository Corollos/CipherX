"""
CIPHER-X Risk Scoring

Converts security detections into a numerical risk score
and corresponding severity level.
"""


SEVERITY_SCORES = {
    "low": 10,
    "medium": 20,
    "high": 40,
    "critical": 70,
}


def calculate_risk_score(detections):
    """
    Calculate a risk score from a list of detections.

    Args:
        detections: List of detection dictionaries.

    Returns:
        Integer risk score.
    """

    score = 0

    for detection in detections:
        severity = detection.get("severity", "low").lower()
        score += SEVERITY_SCORES.get(severity, 0)

    return score


def get_risk_level(score):
    """
    Convert a numerical score into a risk level.

    Args:
        score: Numerical risk score.

    Returns:
        Risk level string.
    """

    if score >= 80:
        return "critical"

    if score >= 60:
        return "high"

    if score >= 30:
        return "medium"

    return "low"