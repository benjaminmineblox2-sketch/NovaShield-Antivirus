"""NovaShield command-line entry point for Windows."""

from __future__ import annotations

import sys
from pathlib import Path

from engine.process_monitor import ProcessMonitor
from engine.scanner import ScanEngine
from realtime.file_watcher import RealtimeProtection


def print_header() -> None:
    print("\n=== NovaShield Antivirus ===")
    print("Windows-focused educational antivirus project")


def prompt_path() -> Path | None:
    raw_path = input("Enter a file or folder path: ").strip().strip('"')
    if not raw_path:
        return None
    path = Path(raw_path)
    if not path.exists():
        print("Path not found.")
        return None
    return path


def main() -> int:
    engine = ScanEngine()
    realtime = RealtimeProtection(engine)
    process_monitor = ProcessMonitor(engine.logger)

    actions = {
        "1": "Scan a file or folder",
        "2": "Run full system scan",
        "3": "Start real-time protection",
        "4": "Stop real-time protection",
        "5": "Run process inspection",
        "6": "Show quarantine records",
        "0": "Exit",
    }

    while True:
        print_header()
        for key, label in actions.items():
            print(f"{key}. {label}")

        choice = input("\nChoose an option: ").strip()

        if choice == "1":
            target = prompt_path()
            if target is None:
                input("Press Enter to continue...")
                continue
            report = engine.scan_path(target)
            print(report.format_summary())
        elif choice == "2":
            print("Starting full system scan. This can take a long time.")
            report = engine.full_system_scan()
            print(report.format_summary())
        elif choice == "3":
            target = prompt_path()
            if target is None:
                input("Press Enter to continue...")
                continue
            realtime.start(target)
            print(f"Real-time protection started for: {target}")
        elif choice == "4":
            realtime.stop()
            print("Real-time protection stopped.")
        elif choice == "5":
            findings = process_monitor.inspect_processes()
            if not findings:
                print("No suspicious processes were detected.")
            else:
                print("\nSuspicious processes:")
                for finding in findings:
                    print(f"- {finding}")
        elif choice == "6":
            records = engine.quarantine_manager.list_records()
            if not records:
                print("Quarantine is empty.")
            else:
                print("\nQuarantine records:")
                for record in records:
                    print(f"- {record['original_path']} -> {record['quarantined_name']}")
        elif choice == "0":
            realtime.stop()
            print("NovaShield closed.")
            return 0
        else:
            print("Invalid option.")

        input("\nPress Enter to continue...")


if __name__ == "__main__":
    sys.exit(main())
