# File Integrity Monitor (FIM)

[![Tests](https://github.com/SaihanLob/File-Integrity-Monitor/actions/workflows/tests.yml/badge.svg)](https://github.com/SaihanLob/File-Integrity-Monitor/actions/workflows/tests.yml)

A lightweight, cross-platform File Integrity Monitor written in Python. It detects unauthorised or unexpected changes to files in a monitored directory using SHA-256 hashing, the same approach used by enterprise tools like OSSEC and Wazuh.

This was built as a blue team and SOC learning project, with the goal of understanding how file change detection works at a fundamental level before moving on to heavier tooling.

## Features

- SHA-256 file hashing (industry standard)
- Detects new, modified, deleted, and unreadable files (making a file unreadable is a way to hide a change, so it is reported rather than skipped)
- Persistent JSON baseline for audit trails
- Timestamped log file output
- Desktop notifications on Windows, Linux, and macOS via `plyer`
- Email alerts via SMTP (compatible with Gmail)
- Continuous watch mode with a configurable scan interval, alerting once per change rather than on every scan
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
git clone https://github.com/SaihanLob/file-integrity-monitor.git
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

Each change is alerted on once. Later scans that find the same change log it as already reported instead of sending another notification or email. If the file changes again, or is restored and then changed later, a new alert is sent.

### 4. Enable Email Alerts

Copy the example config and fill in your credentials:

```bash
cp email.json.example email.json
# Edit email.json with your SMTP settings
python fim.py scan /path/to/monitor --email-config email.json
```

> **Note for Gmail users:** You will need to use an [App Password](https://support.google.com/accounts/answer/185833) rather than your regular account password.

### 5. Sign the Baseline (Recommended)

If an attacker can edit `baseline.json`, they can change a file and then update its hash in the baseline, and every scan will report that nothing has changed. Signing the baseline prevents this.

```bash
python fim.py genkey fim.key
python fim.py baseline /path/to/monitor --key-file fim.key
python fim.py scan /path/to/monitor --key-file fim.key
```

The signature is an HMAC-SHA256 of the baseline contents. Unlike a plain hash, an HMAC cannot be recalculated without the secret key, so an edited baseline cannot be given a valid signature. If the baseline has been edited, or a key is given and the baseline is unsigned, the scan stops with exit code 2 and sends an alert. The key can also be supplied through the `FIM_HMAC_KEY` environment variable. Keep the key where an attacker on the monitored machine cannot read it, ideally on a separate host.

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | No changes |
| `1` | Changes detected |
| `2` | Error: baseline missing, or failed signature verification |

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
[2024-01-15 10:31:05] [WARNING] [UNREADABLE]    /monitored/app.conf
[2024-01-15 10:31:05] [WARNING] 4 new change(s) detected in /monitored
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
| `baseline` / `scan` / `watch` | `--key-file` | Key for signing and verifying the baseline (or set `FIM_HMAC_KEY`) |
| `genkey` | `key_file` | Where to write a new random key (never overwrites an existing file) |

## Real-World Use Cases

File integrity monitoring is a core component of many security frameworks, including PCI-DSS and ISO 27001. Some practical applications include monitoring critical system files such as `/etc` on Linux or exported Windows Registry keys, detecting ransomware activity through a sudden spike in file modifications, auditing web server document roots for signs of defacement, and tracking configuration drift across servers over time.

## Project Structure

```
file-integrity-monitor/
├── fim.py               # Main script
├── requirements.txt     # Python dependencies
├── email.json.example   # Email config template
├── tests/
│   └── test_fim.py      # Automated tests (pytest)
├── .github/workflows/
│   └── tests.yml        # Runs the tests on every push (GitHub Actions)
├── baseline.json        # Generated at runtime (gitignored)
├── fim.key              # Generated by genkey (gitignored)
└── fim.log              # Generated at runtime (gitignored)
```

## Running the Tests

```bash
pip install pytest
python -m pytest
```

The tests cover new, modified, deleted and unreadable files, one alert per change in watch mode, signature verification (including the attack of editing a file's hash in the baseline), and the command line exit codes. They run automatically on Linux and Windows for every push and pull request.

## Security Notes

Never commit `email.json` or key files, as they contain secrets and are listed in `.gitignore` for that reason. Sign the baseline with `--key-file` so it cannot be edited undetected, and store it carefully, ideally read-only or on a separate host. Signing detects an edited baseline, but it cannot stop an attacker with full control of the machine from deleting the baseline or stopping the monitor, which is why production tools send their results to a separate server. For production environments, have a look at [OSSEC](https://www.ossec.net/) or [Wazuh](https://wazuh.com/), which build on these same principles at scale.


## Skills Demonstrated

`Python` · `SHA-256 Hashing` · `File Forensics` · `Alerting & Notification Systems` · `Blue Team / Defensive Security` · `SOC Tooling` · `Cross-platform Development`

## Licence

MIT
