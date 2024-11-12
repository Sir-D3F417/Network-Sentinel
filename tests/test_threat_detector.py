import pytest
import sys
import os
from network_sentinel.threat_detector import ThreatDetector
import numpy as np

def test_threat_detector_init():
    detector = ThreatDetector()
    assert hasattr(detector, 'isolation_forest')
    assert hasattr(detector, 'classifier')
    assert not detector.is_anomaly_trained
    assert not detector.is_classifier_trained

def test_feature_analysis():
    detector = ThreatDetector()
    features = np.zeros(6)  # Create dummy features
    result, attack_type = detector.analyze_packet(features)
    assert isinstance(result, bool)
  
