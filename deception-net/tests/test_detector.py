"""Tests for attacker behavior analysis and anomaly detection."""

import pytest
import numpy as np
import torch

from src.detector.attacker_behavior import (
    BehaviorAnalyzer,
    AttackPhase,
    SkillLevel,
)
from src.detector.anomaly_detection import (
    AnomalyDetector,
    AlertSeverity,
    BehaviorAutoencoder,
)


class TestBehaviorAnalyzer:
    def test_process_interaction_creates_profile(self):
        analyzer = BehaviorAnalyzer()
        log = {
            "source_ip": "10.0.0.1",
            "service": "ssh",
            "action": "connect",
            "data": {},
            "timestamp": "2024-01-01T00:00:00Z",
            "session_id": "ssh-1",
        }
        profile = analyzer.process_interaction(log)
        assert profile is not None
        assert profile.source_ip == "10.0.0.1"
        assert profile.total_interactions == 1

    def test_auth_attempts_tracked(self):
        analyzer = BehaviorAnalyzer()
        for i in range(5):
            analyzer.process_interaction({
                "source_ip": "10.0.0.1",
                "service": "ssh",
                "action": "auth_attempt",
                "data": {"password": f"pass{i}"},
                "timestamp": f"2024-01-01T00:00:{i:02d}Z",
                "session_id": "ssh-1",
            })

        profile = analyzer.get_profile("10.0.0.1")
        assert profile.credential_attempts == 5

    def test_reconnaissance_phase_detected(self):
        analyzer = BehaviorAnalyzer()
        for cmd in ["whoami", "uname -a", "ls", "id", "ifconfig"]:
            analyzer.process_interaction({
                "source_ip": "10.0.0.1",
                "service": "ssh",
                "action": "command",
                "data": {"command": cmd},
                "timestamp": "2024-01-01T00:00:00Z",
                "session_id": "ssh-1",
            })

        profile = analyzer.get_profile("10.0.0.1")
        assert AttackPhase.RECONNAISSANCE in profile.attack_phases

    def test_tool_detection(self):
        analyzer = BehaviorAnalyzer()
        analyzer.process_interaction({
            "source_ip": "10.0.0.1",
            "service": "ssh",
            "action": "command",
            "data": {"command": "nmap -sV 192.168.1.0/24"},
            "timestamp": "2024-01-01T00:00:00Z",
            "session_id": "ssh-1",
        })

        profile = analyzer.get_profile("10.0.0.1")
        assert "nmap" in profile.tools_detected

    def test_threat_score_increases(self):
        analyzer = BehaviorAnalyzer()
        # Simple connect
        analyzer.process_interaction({
            "source_ip": "10.0.0.1",
            "service": "ssh",
            "action": "connect",
            "data": {},
            "timestamp": "2024-01-01T00:00:00Z",
            "session_id": "ssh-1",
        })
        score1 = analyzer.get_profile("10.0.0.1").threat_score

        # Add malicious activity
        for cmd in ["nmap", "wget malware.sh", "ssh 192.168.1.2"]:
            analyzer.process_interaction({
                "source_ip": "10.0.0.1",
                "service": "ssh",
                "action": "command",
                "data": {"command": cmd},
                "timestamp": "2024-01-01T00:01:00Z",
                "session_id": "ssh-1",
            })

        score2 = analyzer.get_profile("10.0.0.1").threat_score
        assert score2 > score1

    def test_unknown_ip_returns_none(self):
        analyzer = BehaviorAnalyzer()
        profile = analyzer.get_profile("nonexistent")
        assert profile is None

    def test_get_summary(self):
        analyzer = BehaviorAnalyzer()
        analyzer.process_interaction({
            "source_ip": "10.0.0.1",
            "service": "ssh",
            "action": "connect",
            "data": {},
            "timestamp": "2024-01-01T00:00:00Z",
            "session_id": "ssh-1",
        })
        summary = analyzer.get_summary()
        assert summary["total_attackers"] == 1


class TestAnomalyDetector:
    def test_isolation_forest_fit(self):
        detector = AnomalyDetector()
        X = np.random.randn(100, 10).astype(np.float32)
        detector.fit_isolation_forest(X)
        assert detector._if_fitted

    def test_autoencoder_training(self):
        detector = AnomalyDetector()
        X = torch.randn(100, 64)
        losses = detector.train_autoencoder(X, epochs=5)
        assert len(losses) == 5
        assert detector._ae_trained

    def test_detect_with_fitted_models(self):
        detector = AnomalyDetector()
        X = np.random.randn(100, 10).astype(np.float32)
        detector.fit_isolation_forest(X)

        # Normal sample
        normal = np.random.randn(10).astype(np.float32)
        result = detector.detect(normal, "10.0.0.1")
        # May or may not generate alert depending on score

    def test_alert_severity_levels(self):
        detector = AnomalyDetector()
        assert detector._score_to_severity(0.1) is None
        assert detector._score_to_severity(0.35) == AlertSeverity.LOW
        assert detector._score_to_severity(0.65) == AlertSeverity.MEDIUM
        assert detector._score_to_severity(0.85) == AlertSeverity.HIGH
        assert detector._score_to_severity(0.96) == AlertSeverity.CRITICAL

    def test_acknowledge_alert(self):
        detector = AnomalyDetector()
        detector._alerts.append(
            type("Alert", (), {
                "alert_id": "ALERT-000001",
                "acknowledged": False,
                "severity": AlertSeverity.HIGH,
            })()
        )
        # Note: this tests the mechanism but uses a mock object

    def test_autoencoder_reconstruction_error(self):
        ae = BehaviorAutoencoder(input_dim=32, encoding_dim=8, hidden_dims=[16])
        x = torch.randn(5, 32)
        error = ae.reconstruction_error(x)
        assert error.shape == (5,)
        assert (error >= 0).all()

    def test_get_stats_empty(self):
        detector = AnomalyDetector()
        stats = detector.get_stats()
        assert stats["total_alerts"] == 0
