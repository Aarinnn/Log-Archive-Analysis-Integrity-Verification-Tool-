#!/usr/bin/env python3

import argparse
from pathlib import Path
from collections import Counter, deque
import gzip
import brotli
import re
import sqlite3

# Regex patterns for SSH authentication logs
FAILED_RE = re.compile(
    r"Failed\s+\S+\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)

ACCEPTED_RE = re.compile(
    r"Accepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)",
    re.IGNORECASE,
)


def open_log_file(path: Path):
    """Return a file object for .log or .log.gz."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    else:
        return path.open("r", errors="ignore")


def _is_plausible_ip(token: str) -> bool:
    """Basic sanity check for IPv4/IPv6-like tokens."""
    return "." in token or ":" in token

def create_database(db_path: str):
    # This will create sql database if they dont exist
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Create a table for all the failed logins 
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT,
            log_file TEXT
        )
    ''')
    
    # Creates a table for successful logins
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS successful_logins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            username TEXT,
            ip_address TEXT,
            log_file TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print(f"Database created/verified at: {db_path}")

def analyze_auth(path: Path, threshold: int = 3, db_path: str = "auth_logs.db"):
    # Creates databases and tables
    create_database(db_path)

    # Connect to database in order to insert data
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    failed_by_ip = Counter()
    failed_by_user = Counter()
    successes = deque(maxlen=10)   # keep only last 10 successful logins

    with open_log_file(path) as f:
        for line in f:
            line = line.strip()

            # failed logins (regex handles all formats)
            m_fail = FAILED_RE.search(line)
            if m_fail:
                ip = m_fail.group("ip")
                user = m_fail.group("user")

                # IP validation
                if _is_plausible_ip(ip):
                    failed_by_ip[ip] += 1

                failed_by_user[user] += 1
                # inserts into the database
                cursor.execute('''
                               INSERT INTO failed_logins (timestamp, username, ip_address, log_file)
                               VALUES (?,?,?,?)
                               ''', (line[:15], user, ip, str(path.name)))
                continue

            # successful logins (any Accepted <method>)
            m_ok = ACCEPTED_RE.search(line)
            if m_ok:
                user = m_ok.group("user")
                ip = m_ok.group("ip")

                successes.append(line)
                # inset database just like before
                cursor.execute('''
                               INSERT INTO successful_logins (timestamp, username, ip_address, log_file)
                               VALUES (?,?,?,?)
                               ''', (line[:15], user, ip, str(path.name)))
                continue

    # Final report
    print("=== Top Failed Login IPs ===")
    for ip, count in failed_by_ip.most_common(10):
        print(f"{ip}: {count}")
    if not failed_by_ip:
        print("none")

    print(f"\n=== Suspicious IPs (>= {threshold} failures) ===")
    flagged = False
    for ip, count in failed_by_ip.items():
        if count >= threshold:
            print(f"{ip}: {count}")
            flagged = True
    if not flagged:
        print("none")

    print("\n=== Users Targeted in Failures ===")
    for user, count in failed_by_user.most_common(10):
        print(f"{user}: {count}")
    if not failed_by_user:
        print("none")

    print("\n=== Recent Successful Logins ===")
    if successes:
        for line in successes:
            print(line)
    else:
        print("none")

        # save and close database
    conn.commit()
    cursor.close()
    print(f"\nData has been saved to the database: {db_path}")

def run_threat_queries(db_path: str = "auth_logs.db"):
    # Running some sql queries to detect threats.
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    print("\n" + "="*50)
    print("SQL THREAT ANALYSIS")
    print("="*50)

# IPs with most failed attempts (Brute Force Detection)
    print("\n========== BRUTE FORCE DETECTION (TOP IPS) ==========")
    cursor.execute('''
        SELECT ip_address, COUNT(*) as attempt_count
        FROM failed_logins
        GROUP BY ip_address
        ORDER BY attempt_count DESC
        LIMIT 10
    ''')
    
    results = cursor.fetchall()
    for row in results:
        print(f"IP: {row[0]} - Failed attempts: {row[1]}")

    if not results:
        print("No failed login attempts found.")
#  Most targeted users        
    print("\n========== MOST TARGETED USERS ==========")
    cursor.execute('''
        SELECT username, COUNT(*) as target_count
        FROM failed_logins
        GROUP BY username
        ORDER BY target_count DESC
        LIMIT 10
    ''')
    
    results = cursor.fetchall()
    for row in results:
        print(f"Username: {row[0]} - Targeted {row[1]} times")

# for all the failed logins by time pattern        
    if not results:
        print("No data found")
    print("\n========== FAILED LOGINS EVERY HOUR ==========")
    cursor.execute('''
        SELECT
            SUBSTR(timestamp, 12, 2) as hour,
            COUNT(*) as attempt
        FROM failed_logins
        GROUP BY hour
        ORDER BY attempt DESC
     ''')
    results = cursor.fetchall()
    for row in results:
        print(f"Hour {row[0]}:00 - {row[1]} failed attempts")
    if not results:
        print("No data found")
# IPS that are using different usernames to access        
    print("\n========== IPS USING MULTIPLE USERNAMES ========== ")
    cursor.execute('''
        SELECT
            ip_address,
            COUNT(DISTINCT username) as unique_users,
            COUNT(*) as total_attempts
        FROM failed_logins
        GROUP BY ip_address
        HAVING unique_users > 1
        ORDER BY unique_users DESC
    ''')
    results = cursor.fetchall()
    for row in results:
        print(f"IP: {row[0]} - Tried {row[1]} different usernames ({row[2]} total attempts)")

    if not results:
        print("No scanning behavior detected")                                    
                                                                                

    # Close off the connection
    conn.close()   

def parse_args():
    parser = argparse.ArgumentParser(description="Auth log analyzer")
    parser.add_argument("logfile", help="Path to auth.log or .log.gz file")
    parser.add_argument("--threshold", type=int, default=3, help="Suspicious IP fail count")
    return parser.parse_args()


def main():
    args = parse_args()
    analyze_auth(Path(args.logfile), args.threshold)

# Run SQL threat analysis
    run_threat_queries()

if __name__ == "__main__":
    main()
