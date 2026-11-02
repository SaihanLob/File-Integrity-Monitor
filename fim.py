#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
Cross-platform tool for detecting unauthorized file changes.
Supports desktop notifications and email alerts.
"""

import os
import sys
import json
import hmac
import secrets
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

#  BASELINE SIGNING
#
# If an attacker can edit baseline.json, they can change a file and then update its
# hash in the baseline, and the scan will report nothing. A plain hash of the baseline
# would not help, because the attacker could recalculate it. An HMAC is a hash that
# also needs a secret key, so without the key the attacker cannot produce a valid
# signature for an edited baseline. Keep the key somewhere the attacker cannot reach,
# ideally off the monitored machine.

KEY_ENV_VAR = "FIM_HMAC_KEY"


class BaselineError(Exception):
    """The baseline is missing a signature, or its signature does not match."""


def load_key(key_file: str | None) -> bytes | None:
    """Return the HMAC key from a key file, or the FIM_HMAC_KEY environment variable."""
    if key_file:
        with open(key_file, "rb") as f:
            key = f.read().strip()
        if not key:
            raise BaselineError(f"Key file '{key_file}' is empty")
        return key
    env_key = os.environ.get(KEY_ENV_VAR)
    return env_key.encode() if env_key else None


def generate_key(key_file: str):
    """Write a new random 256-bit key, readable only by the current user where supported."""
    with open(key_file, "x") as f:     # "x" refuses to overwrite an existing key
        f.write(secrets.token_hex(32))
    try:
        os.chmod(key_file, 0o600)
    except OSError:
        pass


def sign_baseline(meta: dict, key: bytes) -> str:
    """HMAC-SHA256 over the baseline contents, excluding the signature itself.
    sort_keys gives the same JSON text every time, so the signature is repeatable."""
    unsigned = {k: v for k, v in meta.items() if k != "signature"}
    message = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def create_baseline(directory: str, baseline_file: str, logger: logging.Logger,
                    key: bytes | None = None) -> dict:
    """Walk directory, hash all files, and save baseline."""
    baseline = {}
    directory = os.path.abspath(directory)

    logger.info(f"Creating baseline for: {directory}")
    unreadable = []

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
            else:
                unreadable.append(fpath)

    # Files that cannot be read are not protected by the baseline, so say so
    # rather than leaving the user to assume everything is being monitored.
    for fpath in unreadable:
        logger.warning(f"[NOT MONITORED] Could not read, so not in baseline: {fpath}")

    meta = {
        "created_at": datetime.now().isoformat(),
        "directory": directory,
        "file_count": len(baseline),
        "files": baseline
    }
    if key:
        meta["signature"] = sign_baseline(meta, key)

    with open(baseline_file, "w") as f:
        json.dump(meta, f, indent=2)

    logger.info(f"Baseline created: {len(baseline)} files saved to '{baseline_file}'"
                + (" (signed)" if key else ""))
    return baseline

def load_baseline(baseline_file: str, key: bytes | None = None,
                  logger: logging.Logger | None = None) -> dict:
    """Load the baseline, verifying its signature when a key is given.
    Raises BaselineError if a key is given and the baseline is unsigned or altered."""
    with open(baseline_file, "r") as f:
        data = json.load(f)

    signature = data.get("signature")
    if key:
        if not signature:
            raise BaselineError(f"Baseline '{baseline_file}' is not signed, but a key was given")
        # compare_digest takes the same time however many characters match, so an
        # attacker cannot guess the signature one character at a time by timing it.
        if not hmac.compare_digest(signature, sign_baseline(data, key)):
            raise BaselineError(f"Baseline '{baseline_file}' has been modified since it was signed")
    elif signature and logger:
        logger.warning("Baseline is signed but no key was given, so it cannot be verified. "
                       f"Use --key-file or set {KEY_ENV_VAR}.")

    return data.get("files", {})


def alert_baseline_error(error: BaselineError, logger: logging.Logger, email_config: dict):
    """A tampered baseline is a security event in itself, so alert on it like a change."""
    logger.critical(f"[BASELINE INVALID] {error}")
    send_desktop_notification("⚠️ FIM Alert", f"Baseline invalid: {error}")
    send_email_alert([{"type": "baseline invalid", "path": str(error)}], email_config, logger)

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
            body_lines.append(f"      Got      : {change.get('actual_hash') or 'file could not be read'}")
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

def change_key(change: dict) -> tuple:
    """Identify a change so the same change is not alerted on twice in watch mode.
    Includes the new hash, so a file that changes again triggers a fresh alert."""
    return (change["type"], change["path"], change.get("actual_hash"))


def log_change(change: dict, logger: logging.Logger):
    labels = {
        "new":        "[NEW FILE]   ",
        "modified":   "[MODIFIED]   ",
        "deleted":    "[DELETED]    ",
        "unreadable": "[UNREADABLE] ",
    }
    logger.warning(f"{labels[change['type']]}  {change['path']}")
    if change["type"] == "modified":
        logger.warning(f"  Expected hash : {change['expected_hash']}")
        logger.warning(f"  Actual hash   : {change['actual_hash']}")
    elif change["type"] == "unreadable":
        logger.warning("  File can no longer be read. Its contents cannot be verified, "
                       "which is what an attacker hiding a change would want.")
    elif change["type"] == "new" and change.get("actual_hash") is None:
        logger.warning("  New file cannot be read, so its contents are unknown.")


def scan(directory: str, baseline: dict, logger: logging.Logger, email_config: dict,
         already_reported: set | None = None) -> list:
    """Compare current state against baseline and return every change found.

    Alerts (log warnings, desktop notification, email) are sent only for changes
    not in `already_reported`. Watch mode passes in the changes from the previous
    scan, so a change is alerted on once rather than every interval.
    """
    changes = []
    directory = os.path.abspath(directory)
    current_files = set()
    already_reported = already_reported or set()

    for root, _, files in os.walk(directory):
        for fname in files:
            fpath = os.path.join(root, fname)
            current_files.add(fpath)
            current_hash = hash_file(fpath)

            if fpath not in baseline:
                # A new file is reported even if it cannot be read
                changes.append({"type": "new", "path": fpath, "actual_hash": current_hash})

            elif current_hash is None:
                # Previously this was skipped silently, so making a file unreadable
                # (for example with chmod 000) hid any change to it.
                changes.append({
                    "type": "unreadable",
                    "path": fpath,
                    "expected_hash": baseline[fpath]["hash"],
                })

            elif baseline[fpath]["hash"] != current_hash:
                changes.append({
                    "type": "modified",
                    "path": fpath,
                    "expected_hash": baseline[fpath]["hash"],
                    "actual_hash": current_hash
                })

    # Check for deleted files
    for fpath in baseline:
        if fpath not in current_files:
            changes.append({"type": "deleted", "path": fpath})

    new_changes = [c for c in changes if change_key(c) not in already_reported]

    for change in new_changes:
        log_change(change, logger)

    if new_changes:
        summary = f"{len(new_changes)} new change(s) detected in {directory}"
        logger.warning(summary)

        send_desktop_notification("⚠️ FIM Alert", summary)
        send_email_alert(new_changes, email_config, logger)
    elif changes:
        logger.info(f"No new changes in {directory} ({len(changes)} already reported)")
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

  Sign the baseline so it cannot be edited undetected:
    python fim.py genkey fim.key
    python fim.py baseline /path/to/monitor --key-file fim.key
    python fim.py scan /path/to/monitor --key-file fim.key

Exit codes: 0 = no changes, 1 = changes found, 2 = error (missing or invalid baseline)
        """
    )

    subparsers = parser.add_subparsers(dest="command", required=True)
    key_help = f"Key for signing/verifying the baseline (or set {KEY_ENV_VAR})"

    # genkey
    gp = subparsers.add_parser("genkey", help="Generate a key for signing the baseline")
    gp.add_argument("key_file", help="Where to write the new key (will not overwrite)")

    # baseline
    bp = subparsers.add_parser("baseline", help="Create a new baseline")
    bp.add_argument("directory", help="Directory to baseline")
    bp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    bp.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    bp.add_argument("--key-file", default=None, help=key_help)

    # scan
    sp = subparsers.add_parser("scan", help="Run a one-time integrity scan")
    sp.add_argument("directory", help="Directory to scan")
    sp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    sp.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    sp.add_argument("--email-config", default=None, help="Path to email config JSON")
    sp.add_argument("--key-file", default=None, help=key_help)

    # watch
    wp = subparsers.add_parser("watch", help="Continuously monitor a directory")
    wp.add_argument("directory", help="Directory to monitor")
    wp.add_argument("--baseline-file", default=DEFAULT_BASELINE_FILE)
    wp.add_argument("--log-file", default=DEFAULT_LOG_FILE)
    wp.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help="Seconds between scans")
    wp.add_argument("--email-config", default=None)
    wp.add_argument("--key-file", default=None, help=key_help)

    args = parser.parse_args()

    if args.command == "genkey":
        try:
            generate_key(args.key_file)
        except FileExistsError:
            print(f"'{args.key_file}' already exists. Not overwriting it.")
            sys.exit(2)
        print(f"Key written to '{args.key_file}'. Keep it private and never commit it.")
        return

    logger = setup_logging(args.log_file)
    logger.info(f"File Integrity Monitor started — OS: {platform.system()} {platform.release()}")

    try:
        key = load_key(args.key_file)
    except (OSError, BaselineError) as e:
        logger.error(f"Could not load key: {e}")
        sys.exit(2)

    if args.command == "baseline":
        create_baseline(args.directory, args.baseline_file, logger, key)

    elif args.command == "scan":
        if not os.path.exists(args.baseline_file):
            logger.error(f"Baseline file not found: '{args.baseline_file}'. Run 'baseline' first.")
            sys.exit(2)
        email_cfg = load_email_config(args.email_config)
        try:
            baseline = load_baseline(args.baseline_file, key, logger)
        except BaselineError as e:
            alert_baseline_error(e, logger, email_cfg)
            sys.exit(2)
        changes = scan(args.directory, baseline, logger, email_cfg)
        sys.exit(1 if changes else 0)

    elif args.command == "watch":
        if not os.path.exists(args.baseline_file):
            logger.error(f"Baseline file not found: '{args.baseline_file}'. Run 'baseline' first.")
            sys.exit(2)
        email_cfg = load_email_config(args.email_config)
        logger.info(f"Watching '{args.directory}' every {args.interval}s. Press Ctrl+C to stop.")
        reported = set()
        try:
            while True:
                # Reloaded (and re-verified) every scan, so tampering mid-watch is caught
                try:
                    baseline = load_baseline(args.baseline_file, key, logger)
                except BaselineError as e:
                    alert_baseline_error(e, logger, email_cfg)
                    sys.exit(2)
                changes = scan(args.directory, baseline, logger, email_cfg, reported)
                # Remember what is currently changed. If a file is restored, it drops
                # out of this set, so a later change to it will alert again.
                reported = {change_key(c) for c in changes}
                time.sleep(args.interval)
        except KeyboardInterrupt:
            logger.info("FIM stopped by user.")

if __name__ == "__main__":
    main()
