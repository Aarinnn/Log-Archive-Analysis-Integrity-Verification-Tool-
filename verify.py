#!/usr/bin/env python3

import hashlib
from pathlib import Path

archive_folder = Path.home() / "log-archive"

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

# Find all correct .sha256 files
hash_files = list(archive_folder.glob("*.gz.sha256"))

if not hash_files:
    print("No .gz.sha256 files found.")
    raise SystemExit

for hash_file in hash_files:
    # each .sha256 has: "<hash> <filename>"
    parts = hash_file.read_text().strip().split()
    recorded_hash = parts[0]
    gz_name = parts[1]

    gz_path = archive_folder / gz_name

    if not gz_path.exists():
        print(f"[MISSING] {gz_name}")
        continue

    actual_hash = sha256_file(gz_path)

    if actual_hash == recorded_hash:
        print(f"[OK]       {gz_name}")
    else:
        print(f"[MODIFIED] {gz_name}")
