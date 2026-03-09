# NovaShield

NovaShield is a beginner-friendly Windows antivirus project written in Python. It demonstrates real-time file monitoring, full system scans, hash-based detection, basic spyware and keylogger heuristics, process monitoring, quarantine handling, JSON-based signatures, and logging.

## Project Structure

```text
NovaShield/
|-- antivirus.py
|-- engine/
|   |-- scanner.py
|   `-- process_monitor.py
|-- realtime/
|   `-- file_watcher.py
|-- detection/
|   |-- signature_detector.py
|   `-- heuristics.py
|-- quarantine/
|   |-- manager.py
|   |-- quarantine_records.json
|   `-- storage/
|-- database/
|   |-- signature_db.py
|   `-- signatures.json
`-- logs/
    |-- logger.py
    `-- novashield.log
```

## How It Works

- `antivirus.py` provides a simple command-line menu.
- `engine/scanner.py` performs scans and sends infected files to quarantine.
- `engine/process_monitor.py` checks Windows processes for suspicious names, paths, and keylogger-related command lines.
- `realtime/file_watcher.py` watches files with a polling loop and scans files when they change.
- `detection/signature_detector.py` calculates SHA-256 hashes and compares them against the JSON signature database.
- `detection/heuristics.py` performs basic spyware and keylogger detection using names, file extensions, and file content.
- `quarantine/manager.py` safely moves infected files into `quarantine/storage` and writes metadata to `quarantine_records.json`.
- `logs/logger.py` writes events to `logs/novashield.log`.

## Run in Visual Studio Code

1. Open the project folder in Visual Studio Code.
2. Make sure Python 3.11+ is installed on Windows.
3. Open a terminal in VS Code.
4. Run:

```powershell
python antivirus.py
```

## Add or Update Malware Signatures

Open `database/signatures.json` and add more SHA-256 hashes to the `hashes` section:

```json
"0123456789abcdef...": "Example malware family"
```

You can also extend `spyware_keywords` and `content_indicators` with your own detection rules.

## Build an EXE with PyInstaller

If you already have `dist/Antivirus.exe`, you can keep using it. To rebuild from source:

1. Install PyInstaller:

```powershell
pip install pyinstaller
```

2. Build the executable:

```powershell
pyinstaller --onefile --name NovaShield antivirus.py
```

3. The new executable will be created in the `dist` folder.

## Create a Windows Installer with Inno Setup

If you already have an `.iss` script, you can adapt it. To create a fresh installer:

1. Install Inno Setup.
2. Create a script file named `NovaShield.iss` with content similar to this:

```ini
[Setup]
AppName=NovaShield
AppVersion=1.0
DefaultDirName={autopf}\NovaShield
DefaultGroupName=NovaShield
OutputDir=dist
OutputBaseFilename=NovaShieldInstaller
Compression=lzma
SolidCompression=yes

[Files]
Source: "dist\NovaShield.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NovaShield"; Filename: "{app}\NovaShield.exe"
Name: "{commondesktop}\NovaShield"; Filename: "{app}\NovaShield.exe"
```

3. Open the `.iss` file in Inno Setup and click `Build`.

## Notes

- This project is educational and not a replacement for commercial antivirus software.
- A full system scan can take a long time on large drives.
- Heuristic detection can create false positives, so quarantine is safer than deleting files.
