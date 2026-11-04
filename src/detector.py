from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta

from src.log_parser import LoginAttempt


@dataclass
class SecurityAlert:
    ip_address: str
    username: str
    failed_attempts: int
    start_time: object
    end_time: object
    message: str


def detect_suspicious_activity(
    attempts,
    threshold=5,
    time_window_minutes=5
):

    if threshold < 1:
        raise ValueError("Threshold must be at least 1.")

    if time_window_minutes <= 0:
        raise ValueError("Time window must be positive.")

    grouped_attempts = defaultdict(list)

    # Group failed login attempts by IP address.
    for attempt in attempts:

        if attempt.status == "FAILED":
            grouped_attempts[attempt.ip_address].append(attempt)

    alerts = []

    time_window = timedelta(
        minutes=time_window_minutes
    )

    # Analyse each IP address.
    for ip_address, ip_attempts in grouped_attempts.items():

        ip_attempts.sort(
            key=lambda attempt: attempt.timestamp
        )

        left = 0

        for right in range(len(ip_attempts)):

            # Keep only attempts inside the time window.
            while (
                ip_attempts[right].timestamp
                - ip_attempts[left].timestamp
                > time_window
            ):
                left += 1

            current_window = ip_attempts[left:right + 1]

            if len(current_window) >= threshold:

                first_attempt = current_window[0]
                last_attempt = current_window[-1]

                usernames = sorted({
                    attempt.username
                    for attempt in current_window
                })

                alerts.append(
                    SecurityAlert(
                        ip_address=ip_address,
                        username=", ".join(usernames),
                        failed_attempts=len(current_window),
                        start_time=first_attempt.timestamp,
                        end_time=last_attempt.timestamp,
                        message=(
                            f"Detected {len(current_window)} "
                            f"failed login attempts from {ip_address}."
                        )
                    )
                )

                # One alert per IP address.
                break

    return alerts