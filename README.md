# File Integrity Monitor (FIM)
A lightweight, cross-platform File Integrity Monitor written in Python. It detects unauthorised or unexpected changes to files in a monitored directory using SHA-256 hashing, the same approach used by enterprise tools like OSSEC and Wazuh.
This was built as a blue team and SOC learning project, with the goal of understanding how file change detection works at a fundamental level before moving on to heavier tooling.

# Features
1) SHA-256 file hashing (industry standard)
2) Detects new, modified, and deleted files
3) Persistent JSON baseline for audit trails
4) Timestamped log file output
5) Desktop notifications on Windows, Linux, and macOS via plyer
6) Email alerts via SMTP (compatible with Gmail)
7) Continuous watch mode with a configurable scan interval
8) Cross-platform support: Windows and Linux
