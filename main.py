"""Entry point: pick the right collector for this OS, run brute-force
detection, and print a report. `python main.py` works unmodified on
both Windows and Linux.

On Linux, optionally pass a log file path (default: /var/log/auth.log):
    python main.py data/sudo_events.txt
"""
import platform
import sys

from log_pipeline.detector import detect_brute_force, group_failures_by_user


def build_collector():
    system = platform.system()
    if system == "Windows":
        from log_pipeline.collectors.windows import WindowsCollector
        return WindowsCollector()
    elif system == "Linux":
        from log_pipeline.collectors.linux import LinuxCollector
        log_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/auth.log"
        return LinuxCollector(log_path)
    else:
        raise RuntimeError(f"Unsupported platform: {system}")


def main() -> None:
    collector = build_collector()
    events = list(collector.collect())
    print(f"Parsed {len(events)} events.")

    failures_by_user = group_failures_by_user(events)
    for user, user_events in failures_by_user.items():
        print(f"{user}: {len(user_events)} failures")

    suspects = detect_brute_force(events)
    if suspects:
        print("\nBrute-force suspects:")
        for user, user_events in suspects.items():
            print(f"  {user} ({len(user_events)} failures)")
    else:
        print("\nNo brute-force patterns detected.")


if __name__ == "__main__":
    main()
