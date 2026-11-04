from datetime import datetime, timedelta

from src.log_parser import LoginAttempt
from src.detector import detect_suspicious_activity


def create_attempt(
    minutes,
    status="FAILED",
    ip="192.0.2.15",
    username="maria"
):

    return LoginAttempt(
        timestamp=datetime(2026, 11, 4, 9, 0, 0)
        + timedelta(minutes=minutes),
        username=username,
        ip_address=ip,
        status=status
    )


def test_detects_five_failed_attempts():

    attempts = [
        create_attempt(0),
        create_attempt(1),
        create_attempt(2),
        create_attempt(3),
        create_attempt(4)
    ]

    alerts = detect_suspicious_activity(attempts)

    assert len(alerts) == 1
    assert alerts[0].ip_address == "192.0.2.15"
    assert alerts[0].failed_attempts == 5


def test_does_not_alert_below_threshold():

    attempts = [
        create_attempt(0),
        create_attempt(1),
        create_attempt(2),
        create_attempt(3)
    ]

    alerts = detect_suspicious_activity(attempts)

    assert len(alerts) == 0


def test_successful_logins_are_ignored():

    attempts = [
        create_attempt(0, status="SUCCESS"),
        create_attempt(1, status="SUCCESS"),
        create_attempt(2, status="SUCCESS"),
        create_attempt(3, status="SUCCESS"),
        create_attempt(4, status="SUCCESS")
    ]

    alerts = detect_suspicious_activity(attempts)

    assert len(alerts) == 0


def test_attempts_outside_time_window():

    attempts = [
        create_attempt(0),
        create_attempt(6),
        create_attempt(12),
        create_attempt(18),
        create_attempt(24)
    ]

    alerts = detect_suspicious_activity(attempts)

    assert len(alerts) == 0


def test_different_ips_are_analysed_separately():

    attempts = [
        create_attempt(0, ip="192.0.2.15"),
        create_attempt(1, ip="192.0.2.15"),
        create_attempt(2, ip="192.0.2.15"),
        create_attempt(3, ip="198.51.100.20"),
        create_attempt(4, ip="198.51.100.20")
    ]

    alerts = detect_suspicious_activity(attempts)

    assert len(alerts) == 0


def test_invalid_threshold():

    try:
        detect_suspicious_activity([], threshold=0)
        assert False, "Expected ValueError"

    except ValueError:
        assert True