** Log Archive Analysis & Integrity Verification Tool **

A lightweight Python project for analyzing Linux authentication logs and
verifying the integrity of archived log files. Supports both plain log files
and compressed log.gz archives. Provides failed login insights,suspicious IP
detection and SHA-256 integrity checking.

* Requirements -

# Python
# A linux Environment
# Log Files 
# .gz.sha256 files for integrity verification

Python libraries used are ( gzip, hashlib, argparse, pathlib )

* Project Structure - 

This project contains two main tools:

# auth_analyzer.py
An authentication log analysis tool that examines SSH login activity, failed login attempts, targeted usernames, and suspicious IP behavior.

# verify.py
A SHA-256 integrity checker that validates .gz log archives against their .sha256 digest files to detect tampered or missing logs.

# sample_auth.log
A small example log used for testing.

~/log-archive/
    auth_*.log.gz
    syslog_*.gz
    kern_*.log.gz
    *.sha256

* What the Tools do - 

# Authentication Log Analyzer

Scans authentication logs for SSH-related activity

Identifies failed login attempts and counts them by IP address

Highlights usernames repeatedly targeted during brute-force attempts

Flags suspicious IPs based on a user-defined threshold

Displays recent successful login events for correlation

Supports both plain .log and compressed .log.gz formats

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

Authentication Analysis reviews authentication logs to identify failed login attempts, targeted usernames, suspicious IP activity, and recent successful logins.
It helps detect brute-force attempts and unusual SSH behavior.

Integrity Checking checks whether each archived .gz log matches its recorded SHA-256 hash. It quickly shows which logs are intact, altered, or missing.
