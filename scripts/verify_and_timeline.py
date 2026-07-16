#!/usr/bin/env python3
"""
verify_and_timeline.py — minimal host-forensics helper.

Reproduces two core steps of a digital forensic examination on a directory of
collected evidence:

  1. Integrity manifest — MD5 + SHA-256 of every file, so acquisition can be
     proven unaltered later (chain-of-custody baseline).
  2. Access/modify timeline — a chronological listing of file MAC times to help
     reconstruct the sequence of events during an investigation.

Standard library only. Educational/portfolio use on synthetic evidence.
"""
import argparse
import csv
import hashlib
import os
from datetime import datetime, timezone


def hash_file(path, chunk=65536):
    md5, sha = hashlib.md5(), hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(chunk), b""):
            md5.update(block)
            sha.update(block)
    return md5.hexdigest(), sha.hexdigest()


def walk_files(root):
    for dirpath, _, names in os.walk(root):
        for name in names:
            yield os.path.join(dirpath, name)


def build_manifest(root, out_csv):
    rows = []
    for path in walk_files(root):
        try:
            md5, sha = hash_file(path)
            size = os.path.getsize(path)
        except OSError as e:
            print(f"  [skip] {path}: {e}")
            continue
        rows.append({"path": os.path.relpath(path, root), "size_bytes": size,
                     "md5": md5, "sha256": sha})
    _write_csv(out_csv, rows, ["path", "size_bytes", "md5", "sha256"])
    return rows


def build_timeline(root, out_csv):
    rows = []
    for path in walk_files(root):
        try:
            st = os.stat(path)
        except OSError:
            continue
        rows.append({
            "path": os.path.relpath(path, root),
            "modified_utc": _iso(st.st_mtime),
            "accessed_utc": _iso(st.st_atime),
            "changed_utc": _iso(st.st_ctime),
        })
    rows.sort(key=lambda r: r["modified_utc"])
    _write_csv(out_csv, rows, ["path", "modified_utc", "accessed_utc", "changed_utc"])
    return rows


def _iso(ts):
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _write_csv(path, rows, fields):
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def main():
    p = argparse.ArgumentParser(description="Build a hash manifest and MAC-time timeline for an evidence folder.")
    p.add_argument("evidence_dir", help="Folder of collected evidence to analyze")
    p.add_argument("--manifest", default="manifest.csv", help="Output CSV for the hash manifest")
    p.add_argument("--timeline", default="timeline.csv", help="Output CSV for the file timeline")
    args = p.parse_args()

    if not os.path.isdir(args.evidence_dir):
        raise SystemExit(f"Not a directory: {args.evidence_dir}")

    print(f"[*] Examiner run at {_iso(datetime.now().timestamp())}")
    print(f"[*] Evidence root: {os.path.abspath(args.evidence_dir)}")

    manifest = build_manifest(args.evidence_dir, args.manifest)
    print(f"[+] Integrity manifest: {len(manifest)} files hashed -> {args.manifest}")

    timeline = build_timeline(args.evidence_dir, args.timeline)
    print(f"[+] Timeline: {len(timeline)} entries -> {args.timeline}")
    if timeline:
        print("\n[*] Earliest 3 by modified time:")
        for r in timeline[:3]:
            print(f"    {r['modified_utc']}  {r['path']}")


if __name__ == "__main__":
    main()
