# Log Archive Analysis & Integrity Verification Tool

A lightweight Python tool for analyzing Linux authentication logs and verifying log file integrity. Detects brute force attacks, username enumeration, and suspicious login patterns using SQL-based threat detection.

## Features

### Authentication Log Analyzer
- Parses SSH authentication logs (plain `.log` or compressed `.log.gz`)
- Detects failed login attempts and brute force attacks
- Identifies most targeted usernames
- Analyzes attack time patterns
- Detects username enumeration (IPs trying multiple usernames)
- **SQL-powered threat detection** with persistent database storage

### Integrity Verifier
- Validates archived log files using SHA-256 checksums
- Detects tampered or corrupted log archives
- Ensures forensic integrity of log data

## Requirements

- Python 3.8 or higher
- Linux, macOS, or Windows with WSL
- SSH authentication logs (typically `/var/log/auth.log` or `/var/log/secure`)

**No external dependencies required** - uses only Python standard libraries.

## Installation
```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/log-archive-tool.git
cd log-archive-tool
```

## Usage

### Analyze Authentication Logs
```bash
# Analyze current auth log
python3 auth_analyzer.py /var/log/auth.log

# Analyze compressed archive
python3 auth_analyzer.py /var/log/auth.log.1.gz

# Use custom threshold for suspicious IPs (default: 3)
python3 auth_analyzer.py /var/log/auth.log --threshold 10

# Analyze sample data (included)
python3 auth_analyzer.py sample_auth.log
```

### SQL Threat Detection Queries

The tool automatically runs 4 SQL-based threat detection queries:

1. **Brute Force Detection** - Identifies IPs with the most failed login attempts
2. **Most Targeted Usernames** - Shows which accounts attackers are targeting
3. **Time-Based Analysis** - Reveals when attacks occur (by hour)
4. **Username Enumeration** - Detects IPs scanning for valid usernames

All data is stored in `auth_logs.db` (SQLite) for persistent analysis.

### Verify Log Integrity
```bash
# Verify all log archives in a directory
python3 verify.py -d /path/to/log-archive

# Verify with custom digest file pattern
python3 verify.py -d /path/to/logs --pattern "*.sha256"
```

## Example Output
```
========== BRUTE FORCE DETECTION (TOP IPS) ==========
IP: 192.168.1.100 - Failed attempts: 45
IP: 10.0.0.50 - Failed attempts: 12

========== MOST TARGETED USERS ==========
Username: root - Targeted 35 times
Username: admin - Targeted 15 times

========== IPS USING MULTIPLE USERNAMES ==========
IP: 192.168.1.100 - Tried 5 different usernames (45 total attempts)
```

## Project Structure
```
log-archive-tool/
├── auth_analyzer.py          # Main log analysis tool with SQL queries
├── verify.py                 # Integrity verification tool
├── sample_auth.log           # Sample data for testing
├── auth_logs.db             # SQLite database (created on first run)
└── README.md                # This file
```

## Real-World Use Cases

- **Small business servers** - Monitor SSH login attempts without enterprise SIEM
- **Security auditing** - Analyze historical logs for incident investigation
- **Learning environment** - Practice threat detection and log analysis
- **Incident response** - Quickly identify attack patterns and timelines

## Technical Details

- Written in Python 3
- Uses SQLite for data persistence
- Regex-based log parsing for flexibility
- SHA-256 hashing for integrity verification
- Zero external dependencies

## Author

Aarinnn - [GitHub Profile](https://github.com/YOUR_USERNAME)

## License

Open source - feel free to use and modify!