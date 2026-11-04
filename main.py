from pathlib import Path

from src.log_parser import parse_login_logs
from src.detector import detect_suspicious_activity


def main():

    print("=" * 55)
    print("          LOGIN ATTEMPT MONITOR")
    print("          Cybersecurity Tool v1.0")
    print("=" * 55)

    log_file = Path(__file__).parent / "login_attempts.log"

    try:

        attempts = parse_login_logs(log_file)

        print(f"\nTotal login attempts: {len(attempts)}")

        successful = sum(
            1 for attempt in attempts
            if attempt.status == "SUCCESS"
        )

        failed = sum(
            1 for attempt in attempts
            if attempt.status == "FAILED"
        )

        print(f"Successful logins: {successful}")
        print(f"Failed logins: {failed}")

        print("\nAnalysing login activity...")

        alerts = detect_suspicious_activity(
            attempts,
            threshold=5,
            time_window_minutes=5
        )

        print("\n" + "=" * 55)
        print("             SECURITY REPORT")
        print("=" * 55)

        if alerts:

            for alert in alerts:

                print("\n[WARNING] SUSPICIOUS ACTIVITY DETECTED")

                print(f"IP Address: {alert.ip_address}")
                print(f"Username(s): {alert.username}")

                print(
                    f"Failed attempts: {alert.failed_attempts}"
                )

                print(f"Start: {alert.start_time}")
                print(f"End: {alert.end_time}")

                print(f"Details: {alert.message}")

        else:

            print("\nNo suspicious activity detected.")

        print("\n" + "=" * 55)
        print("Analysis completed successfully.")
        print("=" * 55)

    except (FileNotFoundError, ValueError, OSError) as error:

        print(f"\n[ERROR] {error}")


if __name__ == "__main__":
    main()