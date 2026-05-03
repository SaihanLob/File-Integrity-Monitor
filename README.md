# File Integrity Monitor (FIM)

A lightweight, cross-platform File Integrity Monitor written in Python. It detects unauthorised or unexpected changes to files in a monitored directory using SHA-256 hashing, the same approach used by enterprise tools like OSSEC and Wazuh.

This was built as a blue team and SOC learning project, with the goal of understanding how file change detection works at a fundamental level before moving on to heavier tooling.

## Features

- SHA-256 file hashing (industry standard)
- Detects new, modified, and deleted files
- Persistent JSON baseline for audit trails
- Timestamped log file output
- Desktop notifications on Windows, Linux, and macOS via `plyer`
- Email alerts via SMTP (compatible with Gmail)
- Continuous watch mode with a configurable scan interval
- Cross-platform support: Windows and Linux

## How It Works

The tool operates in three stages. First, you create a baseline. It walks the target directory, hashes every file with SHA-256, and saves the results to a JSON file. When you run a scan later, it re-hashes everything and compares the results against that baseline. Any file that has been added, altered, or removed gets flagged, logged, and, if configured, triggers a desktop notification and an email alert.

```
1. Baseline  ->  Hash all files in target directory -> Save to baseline.json
2. Scan      ->  Re-hash all files -> Compare against baseline
3. Alert     ->  Report new / modified / deleted files via log, desktop notification, and email
```

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/file-integrity-monitor.git
cd file-integrity-monitor
pip install -r requirements.txt
```

## Usage

### 1. Create a Baseline

```bash
python fim.py baseline /path/to/monitor
```

This walks the target directory, hashes every file, and saves the results to `baseline.json`. Run this once before you start monitoring, as it becomes your reference point for everything that follows.

### 2. Run a One-Time Scan

```bash
python fim.py scan /path/to/monitor
```

Compares the current state of the directory against your baseline and reports any differences. The process exits with code `1` if changes are found, which makes it straightforward to use in scripts or CI pipelines.

### 3. Continuous Watch Mode

```bash
python fim.py watch /path/to/monitor --interval 30
```

Runs a scan every 30 seconds and keeps going until you press `Ctrl+C`. Useful if you want to leave it running in the background during a session.

### 4. Enable Email Alerts

Copy the example config and fill in your credentials:

```bash
cp email.json.example email.json
# Edit email.json with your SMTP settings
python fim.py scan /path/to/monitor --email-config email.json
```

> **Note for Gmail users:** You will need to use an [App Password](https://support.google.com/accounts/answer/185833) rather than your regular account password.

## Output

### Console and Log File (`fim.log`)

Every event is written to both the terminal and `fim.log` with a timestamp, so you have a full record of everything the tool has seen.

```
[2024-01-15 10:30:01] [INFO]    Baseline created: 42 files saved to 'baseline.json'
[2024-01-15 10:31:05] [WARNING] [NEW FILE]      /monitored/secret.txt
[2024-01-15 10:31:05] [WARNING] [MODIFIED]      /monitored/config.cfg
[2024-01-15 10:31:05] [WARNING]   Expected hash : a3f1e9...
[2024-01-15 10:31:05] [WARNING]   Actual hash   : d7c2b1...
[2024-01-15 10:31:05] [WARNING] [DELETED]       /monitored/important.db
[2024-01-15 10:31:05] [WARNING] 3 change(s) detected in /monitored
```

### Baseline JSON (`baseline.json`)

The baseline is stored as plain JSON, so it is human-readable and easy to inspect or version-control separately.

```json
{
  "created_at": "2024-01-15T10:30:01",
  "directory": "/monitored",
  "file_count": 42,
  "files": {
    "/monitored/config.cfg": {
      "hash": "a3f1e9c2...",
      "size": 1024,
      "modified": 1705312201.0
    }
  }
}
```

## Options Reference

| Command | Option | Description |
|---------|--------|-------------|
| all | `--baseline-file` | Path to baseline JSON (default: `baseline.json`) |
| all | `--log-file` | Path to log output (default: `fim.log`) |
| `scan` / `watch` | `--email-config` | Path to email config JSON |
| `watch` | `--interval` | Seconds between scans (default: `60`) |

## Real-World Use Cases

File integrity monitoring is a core component of many security frameworks, including PCI-DSS and ISO 27001. Some practical applications include monitoring critical system files such as `/etc` on Linux or exported Windows Registry keys, detecting ransomware activity through a sudden spike in file modifications, auditing web server document roots for signs of defacement, and tracking configuration drift across servers over time.

## Project Structure

```
file-integrity-monitor/
├── fim.py               # Main script
├── requirements.txt     # Python dependencies
├── email.json.example   # Email config template
├── baseline.json        # Generated at runtime (gitignored)
└── fim.log              # Generated at runtime (gitignored)
```

## Security Notes

Never commit `email.json`, as it contains credentials and is listed in `.gitignore` for that reason. The baseline file itself should be stored carefully, ideally read-only or on a separate host, so an attacker cannot overwrite it and cover their tracks. For production environments, have a look at [OSSEC](https://www.ossec.net/) or [Wazuh](https://wazuh.com/), which build on these same principles at scale.


## Skills Demonstrated

`Python` · `SHA-256 Hashing` · `File Forensics` · `Alerting & Notification Systems` · `Blue Team / Defensive Security` · `SOC Tooling` · `Cross-platform Development`

## Licence

MIT
