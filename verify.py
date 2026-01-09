#!/usr/bin/env python3

import argparse
import hashlib
from pathlib import Path


def sha256_file(path: Path):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_digest_line(line: str):
    """Parse a single line from a .sha256 file.

    Expected formats (standard sha256sum):
        <hash>  filename
        <hash>  *filename
    Returns (hash, filename) or None if line is not usable.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    parts = line.split(None, 1)
    if len(parts) != 2:
        return None

    recorded_hash, rest = parts
    # removes optional leading '*' used by sha256sum for binary mode
    filename = rest.lstrip("*").strip()
    if not filename:
        return None

    return recorded_hash, filename


def verify_archive(archive_folder: Path, pattern: str = "*.gz.sha256"):
    """Verify all log archives under archive_folder using .sha256 files."""
    if not archive_folder.is_dir():
        print(f"Archive folder not found: {archive_folder}")
        return

    # Find all .sha256 files matching the pattern
    hash_files = list(archive_folder.glob(pattern))

    if not hash_files:
        print(f"No {pattern} files found in {archive_folder}")
        return

    for hash_file in sorted(hash_files):
        try:
            lines = hash_file.read_text().splitlines()
        except OSError as e:
            print(f"[ERROR] Could not read {hash_file.name}: {e}")
            continue

        if not lines:
            print(f"[SKIP]  {hash_file.name} (empty digest file)")
            continue

        for lineno, line in enumerate(lines, start=1):
            parsed = parse_digest_line(line)
            if parsed is None:
                # skip malformed or comment lines
                continue

            recorded_hash, gz_name = parsed
            gz_path = archive_folder / gz_name

            if not gz_path.exists():
                print(f"[MISSING] {gz_name}")
                continue

            actual_hash = sha256_file(gz_path)

            if actual_hash == recorded_hash:
                print(f"[OK]       {gz_name}")
            else:
                print(f"[MODIFIED] {gz_name}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="SHA-256 integrity checker for log archives"
    )
    parser.add_argument(
        "-d",
        "--dir",
        dest="directory",
        default=None,
        help="Path to log-archive directory (default: ~/log-archive)",
    )
    parser.add_argument(
        "--pattern",
        default="*.gz.sha256",
        help="Glob pattern for digest files (default: *.gz.sha256)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # default to ~/log-archive for backward compatibility
    archive_folder = (
        Path(args.directory).expanduser()
        if args.directory
        else Path.home() / "log-archive"
    )

    verify_archive(archive_folder, args.pattern)


if __name__ == "__main__":
    main()


