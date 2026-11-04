import csv
import ipaddress

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


@dataclass
class LoginAttempt:
    timestamp: datetime
    username: str
    ip_address: str
    status: str


def parse_login_logs(file_path):

    attempts = []

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"Log file not found: {file_path}"
        )

    with path.open("r", newline="", encoding="utf-8") as file:

        reader = csv.DictReader(file)

        required_columns = {
            "timestamp",
            "username",
            "ip_address",
            "status"
        }

        if not reader.fieldnames or not required_columns.issubset(reader.fieldnames):
            raise ValueError("Invalid log file format.")

        for line_number, row in enumerate(reader, start=2):

            try:
                timestamp = datetime.fromisoformat(
                    row["timestamp"]
                )

                username = row["username"].strip()

                ip_address = row["ip_address"].strip()

                status = row["status"].strip().upper()

                ipaddress.ip_address(ip_address)

                if not username:
                    raise ValueError("Username cannot be empty.")

                if status not in {"SUCCESS", "FAILED"}:
                    raise ValueError("Invalid login status.")

                attempt = LoginAttempt(
                    timestamp=timestamp,
                    username=username,
                    ip_address=ip_address,
                    status=status
                )

                attempts.append(attempt)

            except (ValueError, TypeError) as error:
                raise ValueError(
                    f"Invalid data on line {line_number}: {error}"
                ) from error

    return attempts