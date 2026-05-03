#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Cross-platform tool for detecting unauthorized file changes.
Supports desktop notifications and email alerts.
"""

import os
import sys
import json
import hashlib
import smtplib
import logging
import argparse
import platform
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path

try:
    from plyer import notification
    PLYER_AVAILABLE = True
except ImportError:
    PLYER_AVAILABLE = False


#  CONFIGURATION

DEFAULT_BASELINE_FILE = "baseline.json"
DEFAULT_LOG_FILE = "fim.log"
DEFAULT_INTERVAL = 60  # seconds between scans in watch mode

#  LOGGING SETUP

def setup_logging(log_file: str) -> logging.Logger:
    logger = logging.getLogger("FIM")
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

    # File handler
    fh = logging.FileHandler(log_file)
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler()
    ch.setFormatter(formatter)
    logger.addHandler(ch)

    return logger

#  HASHING

def hash_file(filepath: str) -> str | None:
    """Return SHA-256 hash of a file, or None if unreadable."""
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None

#  BASELINE

def create_baseline(directory: str, baseline_file: str, logger: logging.Logger) -> dict:
    """Walk directory, hash all files, and save baseline."""
    baseline = {}
    directory = os.path.abspath(directory)

    logger.info(f"Creating baseline for: {directory}")

    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            file_hash = hash_file(fpath)
            if file_hash:
                baseline[fpath] = {
                    "hash": file_hash,
                    "size": os.path.getsize(fpath),
                    "modified": os.path.getmtime(fpath)
                }

    meta = {
        "created_at": datetime.now().isoformat(),
        "directory": directory,
        "file_count": len(baseline),
        "files": baseline
    }

    with open(baseline_file, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Baseline created: {len(baseline)} files saved to '{baseline_file}'")
    return baseline

def load_baseline(baseline_file: str) -> dict:
    """Load existing baseline from JSON file."""
    with open(baseline_file, "r") as f:
        data = json.load(f)
    return data.get("files", {})

#  ALERTS

def send_desktop_notification(title: str, message: str):
    """Send a desktop notification (cross-platform via plyer)."""
    if not PLYER_AVAILABLE:
        return
    try:
        notification.notify(
            title=title,
            message=message,
            app_name="File Integrity Monitor",
            timeout=10
        )
    except Exception:
        pass  # Silently fail if no notification daemon available


def send_email_alert(changes: list, config: dict, logger: logging.Logger):
    """Send an email alert summarising detected changes."""
    if not config.get("enabled"):
        return

    subject = f"[FIM ALERT] {len(changes)} change(s) detected — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"

    body_lines = ["File Integrity Monitor has detected the following changes:\n"]
    for change in changes:
        body_lines.append(f"  [{change['type'].upper()}] {change['path']}")
        if "expected_hash" in change:
            body_lines.append(f"      Expected : {change['expected_hash']}")
            body_lines.append(f"      Got      : {change['actual_hash']}")
        body_lines.append("")

    body = "\n".join(body_lines)

    msg = MIMEMultipart()
    msg["From"] = config["sender"]
    msg["To"] = config["recipient"]
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP_SSL(config["smtp_host"], config.get("smtp_port", 465)) as server:
            server.login(config["sender"], config["password"])
            server.sendmail(config["sender"], config["recipient"], msg.as_string())
        logger.info(f"Email alert sent to {config['recipient']}")
    except Exception as e:
        logger.error(f"Failed to send email alert: {e}")

#  CORE SCAN LOGIC

def scan(directory: str, baseline: dict, logger: logging.Logger, email_config: dict) -> list:
    """Compare current state against baseline. Return list of changes."""
    changes = []
    directory = os.path.abspath(directory)
    current_files = set()

    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            current_files.add(fpath)
            current_hash = hash_file(fpath)

            if current_hash is None:
                continue

            if fpath not in baseline:
                change = {"type": "new", "path": fpath}
                changes.append(change)
                logger.warning(f"[NEW FILE]      {fpath}")

            elif baseline[fpath]["hash"] != current_hash:
                change = {
                    "type": "modified",
                    "path": fpath,
                    "expected_hash": baseline[fpath]["hash"],
                    "actual_hash": current_hash
                }
                changes.append(change)
                logger.warning(f"[MODIFIED]      {fpath}")
                logger.warning(f"  Expected hash : {baseline[fpath]['hash']}")
                logger.warning(f"  Actual hash   : {current_hash}")

    # Check for deleted files
    for fpath in baseline:
        if fpath not in current_files:
            change = {"type": "deleted", "path": fpath}
            changes.append(change)
            logger.warning(f"[DELETED]       {fpath}")

    if changes:
        summary = f"{len(changes)} change(s) detected in {directory}"
        logger.warning(summary)

        send_desktop_notification("⚠️ FIM Alert", summary)
        send_email_alert(changes, email_config, logger)
    else:
        logger.info(f"No changes detected in {directory}")

    return changes

#  EMAIL CONFIG LOADER

def load_email_config(config_path: str) -> dict:
    """Load email config from JSON file. Returns disabled config if not found."""
    if config_path and os.path.exists(config_path):
        with open(config_path, "r") as f:
            cfg = json.load(f)
        cfg["enabled"] = True
        return cfg
    return {"enabled": False}

#  CLI

def main():
    parser = argparse.ArgumentParser(
        description="File Integrity Monitor — detect unauthorized file changes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Create a baseline:
    python fim.py baseline /path/to/monitor

  Run a one-time scan:
    python fim.py scan /path/to/monitor

  Watch continuously (every 60s):
    python fim.py watch /path/to/monitor --interval 60

  Scan with email alerts:
    python fim.py scan /path/to/monitor --email-config email.json
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # baseline
    bp = subparsers.add_parser("baseline", help="Create a new baseline")
    bp.add_argument("directory", help="Directory to baseline")
    bp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    bp.add_argument("--log-file", default=DEFAULT_LOG_FILE)

    # scan
    sp = subparsers.add_parser("scan", help="Run a one-time integrity scan")
    sp.add_argument("directory", help="Directory to scan")
    sp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    sp.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    sp.add_argument("--email-config", default=None, help="Path to email config JSON")

    # watch
    wp = subparsers.add_parser("watch", help="Continuously monitor a directory")
    wp.add_argument("directory", help="Directory to monitor")
    wp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    wp.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    wp.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Seconds between scans")
    wp.add_argument("--email-config", default=None)

    args = parser.parse_args()
    logger = setup_logging(args.log_file)
    logger.info(f"File Integrity Monitor started — OS: {platform.system()} {platform.release()}")

    if args.command == "baseline":
        create_baseline(args.directory, args.baseline_file, logger)

    elif args.command == "scan":
        if not os.path.exists(args.baseline_file):
            logger.error(f"Baseline file not found: '{args.baseline_file}'. Run 'baseline' first.")
            sys.exit(1)
        baseline = load_baseline(args.baseline_file)
        email_cfg = load_email_config(args.email_config)
        changes = scan(args.directory, baseline, logger, email_cfg)
        sys.exit(1 if changes else 0)

    elif args.command == "watch":
        if not os.path.exists(args.baseline_file):
            logger.error(f"Baseline file not found: '{args.baseline_file}'. Run 'baseline' first.")
            sys.exit(1)
        email_cfg = load_email_config(args.email_config)
        logger.info(f"Watching '{args.directory}' every {args.interval}s. Press Ctrl+C to stop.")
        try:
            while True:
                baseline = load_baseline(args.baseline_file)
                scan(args.directory, baseline, logger, email_cfg)
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("FIM stopped by user.")

if __name__ == "__main__":
    main()
