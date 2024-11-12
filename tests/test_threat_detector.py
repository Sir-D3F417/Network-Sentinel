import pytest
from network_sentinel.threat_detector import ThreatDetector

def test_threat_detector_init():
    detector = ThreatDetector()
    assert detector.is_anomaly_trained == False
    assert detector.is_classifier_trained == False 