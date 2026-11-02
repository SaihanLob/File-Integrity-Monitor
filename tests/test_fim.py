"""Tests for the File Integrity Monitor.

Run with:  python -m pytest
"""

import json
import logging
import subprocess
import sys
from pathlib import Path

import pytest

import fim

FIM = Path(__file__).resolve().parent.parent / "fim.py"
NO_EMAIL = {"enabled": False}


@pytest.fixture(autouse=True)
def no_desktop_notifications(monkeypatch):
    """Keep tests from popping up real notifications."""
    monkeypatch.setattr(fim, "send_desktop_notification", lambda title, message: None)


@pytest.fixture
def logger():
    return logging.getLogger("fim-test")


@pytest.fixture
def monitored(tmp_path):
    """A folder with two files, and a path for its baseline outside the folder."""
    folder = tmp_path / "monitored"
    folder.mkdir()
    (folder / "a.txt").write_text("alpha")
    (folder / "b.txt").write_text("bravo")
    return folder, tmp_path / "baseline.json"


def types(changes):
    return sorted((c["type"], Path(c["path"]).name) for c in changes)


# Core detection

def test_no_changes(monitored, logger):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger)
    assert fim.scan(str(folder), fim.load_baseline(str(base)), logger, NO_EMAIL) == []


def test_new_modified_and_deleted(monitored, logger):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger)
    (folder / "a.txt").write_text("changed")
    (folder / "b.txt").unlink()
    (folder / "c.txt").write_text("new")
    changes = fim.scan(str(folder), fim.load_baseline(str(base)), logger, NO_EMAIL)
    assert types(changes) == [("deleted", "b.txt"), ("modified", "a.txt"), ("new", "c.txt")]


def test_unreadable_file_is_reported_not_skipped(monitored, logger, monkeypatch):
    """Simulates chmod 000 by making hash_file fail for b.txt."""
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger)
    real_hash = fim.hash_file
    monkeypatch.setattr(fim, "hash_file",
                        lambda p: None if p.endswith("b.txt") else real_hash(p))
    changes = fim.scan(str(folder), fim.load_baseline(str(base)), logger, NO_EMAIL)
    assert types(changes) == [("unreadable", "b.txt")]


def test_watch_mode_alerts_once_per_change(monitored, logger, caplog):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger)
    (folder / "a.txt").write_text("changed")
    baseline = fim.load_baseline(str(base))

    first = fim.scan(str(folder), baseline, logger, NO_EMAIL)
    reported = {fim.change_key(c) for c in first}

    caplog.clear()
    second = fim.scan(str(folder), baseline, logger, NO_EMAIL, reported)
    assert second == first                                   # still returned
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]   # but no alert

    (folder / "a.txt").write_text("changed again")
    caplog.clear()
    fim.scan(str(folder), baseline, logger, NO_EMAIL, reported)
    assert any("MODIFIED" in r.message for r in caplog.records)             # new change alerts


def test_email_body_handles_unreadable_change(logger, monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, *a, **k): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass
        def login(self, *a): pass
        def sendmail(self, sender, recipient, msg): sent.append(msg)

    monkeypatch.setattr(fim.smtplib, "SMTP_SSL", FakeSMTP)
    config = {"enabled": True, "sender": "a@example.com", "recipient": "b@example.com",
              "password": "x", "smtp_host": "smtp.example.com"}
    fim.send_email_alert([{"type": "unreadable", "path": "/etc/x", "expected_hash": "abc"}],
                         config, logger)
    assert len(sent) == 1


# Signed baseline

def test_signed_baseline_verifies(monitored, logger):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger, key=b"secret")
    assert "signature" in json.loads(base.read_text())
    assert len(fim.load_baseline(str(base), key=b"secret")) == 2


def test_edited_baseline_is_rejected(monitored, logger):
    """The attack this prevents: change a file, then update its hash in the baseline."""
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger, key=b"secret")
    (folder / "a.txt").write_text("backdoored")

    data = json.loads(base.read_text())
    path = str(folder / "a.txt")
    data["files"][path]["hash"] = fim.hash_file(path)
    base.write_text(json.dumps(data))

    with pytest.raises(fim.BaselineError, match="modified"):
        fim.load_baseline(str(base), key=b"secret")


def test_wrong_key_is_rejected(monitored, logger):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger, key=b"secret")
    with pytest.raises(fim.BaselineError):
        fim.load_baseline(str(base), key=b"guess")


def test_unsigned_baseline_rejected_when_key_given(monitored, logger):
    folder, base = monitored
    fim.create_baseline(str(folder), str(base), logger)
    with pytest.raises(fim.BaselineError, match="not signed"):
        fim.load_baseline(str(base), key=b"secret")


def test_key_from_environment(monkeypatch):
    monkeypatch.setenv(fim.KEY_ENV_VAR, "from-env")
    assert fim.load_key(None) == b"from-env"


def test_genkey_will_not_overwrite(tmp_path):
    key = tmp_path / "fim.key"
    fim.generate_key(str(key))
    assert len(key.read_text()) == 64
    with pytest.raises(FileExistsError):
        fim.generate_key(str(key))


# Command line exit codes: 0 no changes, 1 changes, 2 error

def run(*args, cwd):
    return subprocess.run([sys.executable, str(FIM), *args], cwd=cwd,
                          capture_output=True, text=True).returncode


def test_cli_exit_codes(monitored):
    folder, base = monitored
    cwd = base.parent
    common = ["--baseline-file", str(base), "--log-file", str(cwd / "fim.log")]

    assert run("scan", str(folder), *common, cwd=cwd) == 2              # no baseline yet
    assert run("genkey", "fim.key", cwd=cwd) == 0
    assert run("baseline", str(folder), *common, "--key-file", "fim.key", cwd=cwd) == 0
    assert run("scan", str(folder), *common, "--key-file", "fim.key", cwd=cwd) == 0

    (folder / "a.txt").write_text("changed")
    assert run("scan", str(folder), *common, "--key-file", "fim.key", cwd=cwd) == 1

    data = json.loads(base.read_text())
    data["file_count"] = 99
    base.write_text(json.dumps(data))
    assert run("scan", str(folder), *common, "--key-file", "fim.key", cwd=cwd) == 2
