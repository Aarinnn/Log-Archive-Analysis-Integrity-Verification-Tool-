** Log Archive Analysis & Integrity Verification Tool **

A lightweight Python project for analyzing Linux SSH authentication logs and verifying the integrity of archived log files.
Designed as a semi-beginner friendly security project with clean structure, real CLI usage, and zero external dependencies.

Features

Authentication Log Analyzer (auth_analyzer.py)

Parses SSH authentication logs (.log or .log.gz)

Counts failed login attempts by IP and username

Detects suspicious IPs exceeding a configurable threshold

Shows the last 10 successful SSH logins

Uses regex-based extraction for reliability across log formats

Supports both plain and compressed logs

Integrity Verifier (verify.py)

Validates .gz log archives using matching .sha256 digest files

Detects:

OK → file hash matches

MODIFIED → file tampered

MISSING → digest references a file that doesn’t exist

Handles multi-line sha256sum output safely

Uses only Python standard library (hashlib, pathlib)

* Project Structure - 

project/
│
├── auth_analyzer.py          # SSH auth log analysis tool
├── verify.py                 # SHA-256 integrity checker
├── sample_auth.log           # Example SSH log for testing
├── README.md
└── log-archive/              # Example archive directory
    ├── auth_*.log.gz
    ├── kern_*.log.gz
    ├── history_*.log.gz
    ├── syslog_*.gz
    └── *.sha256
Requirements

Python 3.8+

Linux or WSL (Windows Subsystem for Linux)

No external dependencies — only Python standard library:

gzip, hashlib, argparse, pathlib, re, collections    

* What the Tools do - 

# Authentication Log Analyzer

Scans Linux authentication logs for SSH activity and extracts useful security insights.

Identifies failed login attempts and counts them by IP address

Highlights usernames repeatedly targeted during brute-force attempts

Flags suspicious IPs based on a user-defined threshold

Displays recent successful login events for correlation

Supports both plain .log and compressed .log.gz formats

Uses regex-based parsing for reliability across OpenSSH logs

# Integrity Verification

Reads .gz.sha256 digest files

Computes SHA-256 checksums for archived .gz logs

Compares expected vs. actual hashes

Reports logs as:

OK → integrity confirmed

MODIFIED → mismatch detected

MISSING → log referenced by digest not found

This ensures your log archives have not been altered or corrupted before analysis.

* Usage

Authentication Log Analysis

Analyze SSH authentication logs to:

Detect failed login attempts

Identify brute-force behavior

See which users are being targeted

Review recent successful SSH logins

Integrity Checking

python3 verify.py --dir ./log-archive  ( Use this code in bash )
It will quickly show which logs are intact, modified or missing.

