#!/usr/bin/env python3

import argparse
from pathlib import Path
from collections import Counter
import gzip


def open_log_file(path: Path):
    """Return a file object for .log or .log.gz."""
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    if path.suffix == ".gz":
        return gzip.open(path, "rt", errors="ignore")
    else:
        return path.open("r", errors="ignore")


def analyze_auth(path: Path, threshold: int = 3):
    failed_by_ip = Counter()
    failed_by_user = Counter()
    successes = []

    with open_log_file(path) as f:
        for line in f:
            # failed logins
            if "Failed password" in line and "from" in line:
                parts = line.split()

                # IP after 'from'
                if "from" in parts:
                    idx = parts.index("from")
                    if idx + 1 < len(parts):
                        ip = parts[idx + 1]
                        failed_by_ip[ip] += 1

                # invalid user
                if "invalid" in parts and "user" in parts:
                    i = parts.index("invalid")
                    if i + 2 < len(parts) and parts[i+1] == "user":
                        user = parts[i + 2]
                        failed_by_user[user] += 1
                        continue

                # standard 'for <user>'
                if "for" in parts:
                    j = parts.index("for")
                    if j + 1 < len(parts):
                        user = parts[j + 1]
                        failed_by_user[user] += 1

            # successful logins
            if "Accepted password" in line or "Accepted publickey" in line:
                successes.append(line.strip())

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
        for line in successes[-10:]:
            print(line)
    else:
        print("none")


def parse_args():
    parser = argparse.ArgumentParser(description="Beginner-level auth log analyzer")
    parser.add_argument("logfile", help="Path to auth.log or .log.gz file")
    parser.add_argument("--threshold", type=int, default=3, help="Suspicious IP fail count")
    return parser.parse_args()


def main():
    args = parse_args()
    analyze_auth(Path(args.logfile), args.threshold)


if __name__ == "__main__":
    main()
