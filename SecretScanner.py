#!/usr/bin/env python3
"""
secret_scanner.py
CLI tool to scan files/directories for hardcoded secrets using regex patterns.

Usage:
    python secret_scanner.py /path/to/dir --json report.json
"""

import argparse
import logging
import json
import os
import re
from pathlib import Path
from typing import List, Dict, Any

# -------------------------
# Configure logging
# -------------------------
logger = logging.getLogger("secret_scanner")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
ch.setFormatter(formatter)
logger.addHandler(ch)

# -------------------------
# Regex patterns (≥5 examples)
# -------------------------
PATTERNS = {
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA|A3T)[A-Z0-9]{16}\b"),
    "AWS Secret Access Key": re.compile(r"\b[A-Za-z0-9/+=]{40}\b"),
    "Generic API Key (32-48 chars)": re.compile(r"\b[a-zA-Z0-9-_]{32,48}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b"),
    "Private Key (PEM header)": re.compile(r"-----BEGIN (?:RSA )?PRIVATE KEY-----"),
    "OPENSSH Private Key": re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----"),
    "Slack Token": re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]+)\b"),
    "Stripe Secret Key": re.compile(r"\bsk_(live|test)_[0-9a-zA-Z]{24,}\b"),
    "Password assignment": re.compile(
        r"(?:password|pwd|pass|db_password)\s*[:=]\s*['\"]?([^\s'\"#;]{6,})['\"]?",
        flags=re.IGNORECASE,
    ),
}

# -------------------------
# Skip common binary file types
# -------------------------
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".exe", ".dll", ".so",
    ".dylib", ".class", ".jar", ".zip", ".tar", ".gz", ".7z", ".pdf"
}

# -------------------------
# Utility functions
# -------------------------
def is_text_file(path: Path) -> bool:
    """Skip binary files by checking extension and reading a small chunk."""
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return False
    try:
        with open(path, "rb") as f:
            chunk = f.read(1024)
            if b"\0" in chunk:
                return False
    except Exception:
        return False
    return True


def mask_value(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Mask part of a detected secret so full key isn't exposed."""
    if not value:
        return value
    if len(value) <= (keep_start + keep_end + 3):
        return value[0:keep_start] + "..." + value[-keep_end:]
    return value[0:keep_start] + "..." + value[-keep_end:]


def scan_file(path: Path, patterns: Dict[str, re.Pattern], mask: bool = False) -> List[Dict[str, Any]]:
    """Scan a single file line by line for regex pattern matches."""
    findings = []
    try:
        if not is_text_file(path):
            logger.debug("Skipping binary/non-text file: %s", path)
            return findings

        # FIX: ignore bad encodings to prevent UnicodeDecodeError
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, start=1):
                for name, regex in patterns.items():
                    for m in regex.finditer(line):
                        matched = m.group(0)
                        reported = mask_value(matched) if mask else matched
                        findings.append({
                            "file": str(path),
                            "line": lineno,
                            "pattern": name,
                            "match": reported,
                            "raw_match": matched if not mask else None
                        })
    except Exception as e:
        logger.warning("Failed to scan file %s: %s", path, e)
    return findings


def scan_path(
    path: Path,
    patterns: Dict[str, re.Pattern],
    recursive: bool = True,
    mask: bool = False,
    exclude: List[str] = None
) -> List[Dict[str, Any]]:
    """Scan all files in a directory (recursively by default)."""
    if exclude is None:
        exclude = []
    results = []

    if path.is_file():
        logger.info("Scanning file: %s", path)
        results.extend(scan_file(path, patterns, mask=mask))
    else:
        logger.info("Scanning directory: %s", path)
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in files:
                file_path = Path(root) / fname
                if any(part in str(file_path) for part in exclude):
                    continue
                if file_path.suffix.lower() in SKIP_EXTENSIONS:
                    continue
                results.extend(scan_file(file_path, patterns, mask=mask))
            if not recursive:
                break
    return results


# -------------------------
# CLI handling
# -------------------------
def parse_args():
    parser = argparse.ArgumentParser(description="Scan files or directories for hardcoded secrets.")
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument("--json", "-j", dest="json", help="Write findings to JSON file")
    parser.add_argument("--mask", action="store_true", help="Mask matched secrets in output (shows partial values)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--exclude", nargs="*", default=[], help="Paths or directory names to exclude from scanning")
    parser.add_argument("--no-recursive", action="store_true", help="Do not recurse into subdirectories")
    return parser.parse_args()


# -------------------------
# Main function with safe handling
# -------------------------
def main():
    try:
        args = parse_args()
    except SystemExit:
        # Happens when no arguments provided (e.g., F5 in Visual Studio)
        logger.error("Usage: python secret_scanner.py <path_to_scan> [options]")
        logger.info("Example: python secret_scanner.py ./myproject --mask --json report.json")
        return 1

    if args.debug:
        logger.setLevel(logging.DEBUG)
        ch.setLevel(logging.DEBUG)

    path = Path(args.path)
    if not path.exists():
        logger.error("Path does not exist: %s", path)
        return 2

    findings = scan_path(
        path,
        PATTERNS,
        recursive=not args.no_recursive,
        mask=args.mask,
        exclude=args.exclude
    )

    if findings:
        logger.info("Found %d possible secret(s).", len(findings))
        for f in findings:
            print(f"[{f['pattern']}] {f['file']}:{f['line']} -> {f['match']}")
    else:
        logger.info("No secrets found.")

    if args.json:
        try:
            with open(args.json, "w", encoding="utf-8") as outfh:
                json.dump(findings, outfh, indent=2)
            logger.info("Wrote JSON report to %s", args.json)
        except Exception as e:
            logger.error("Failed to write JSON report: %s", e)

    return 0


# -------------------------
# Entry point (Visual Studio-safe)
# -------------------------
if __name__ == "__main__":
    try:
        exit_code = main()
        if exit_code not in (0, None):
            print(f"Exited with code {exit_code}")
    except SystemExit:
        pass  # Suppress harmless debugger popup
    except Exception as e:
        print(f"Unexpected error: {e}")
