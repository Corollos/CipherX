"""
CIPHER-X Correlation Manager

Provides a shared correlation engine for security
detections generated across CIPHER-X monitors.
"""

from agent.detection.correlation import CorrelationEngine


correlation_engine = CorrelationEngine()