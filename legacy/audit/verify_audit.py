"""Validate report coverage and source preservation, optionally rescan GDFA bodies."""
from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import json
from pathlib import Path
import re
import struct
import time

ROOT = Path(__file__).resolve().parents[1]
HERE = Path(__file__).resolve().parent


def read_json(name):
    return json.loads((HERE / name).read_text(encoding="utf-8-sig"))


def full_hashes():
    results = []
    for item in read_json("container_integrity.json"):
        path = ROOT / item["file"]
        started = time.perf_counter()
        with path.open("rb") as handle:
            magic = handle.read(7)
            assert magic == b"ZIDSv1\0", (path, magic)
            header_length = struct.unpack(">I", handle.read(4))[0]
            header = json.loads(handle.read(header_length))
            remaining = header["num_states"] * header["row_bytes"]
            body_bytes = remaining
            digest = hashlib.sha256()
            while remaining:
                block = handle.read(min(8 * 1024 * 1024, remaining))
                if not block:
                    raise ValueError(f"truncated body in {path}")
                digest.update(block)
                remaining -= len(block)
            stored = handle.read(32)
            trailing = handle.read(1)
        results.append(dict(file=item["file"], body_bytes=body_bytes,
                            sha256=digest.hexdigest(), body_hash_matches=digest.digest() == stored,
                            no_trailing_bytes=not trailing,
                            seconds=round(time.perf_counter() - started, 3)))
        print(json.dumps(results[-1]))
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hash-containers", action="store_true")
    parser.add_argument("--out", type=Path, default=HERE / "verification.json")
    args = parser.parse_args()
    snapshot = read_json("file_snapshot.json")
    changed = []
    checked_hashes = 0
    for item in snapshot:
        path = ROOT / item["path"]
        if not path.exists() or path.stat().st_size != item["bytes"]:
            changed.append(item["path"])
        elif item["sha256"]:
            checked_hashes += 1
            if hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]:
                changed.append(item["path"])
    with (HERE / "file_inventory.csv").open(encoding="utf-8-sig", newline="") as handle:
        inventory = list(csv.DictReader(handle))
    assert {x["path"] for x in snapshot} == {x["path"] for x in inventory}
    syntax = []
    for path in sorted(HERE.glob("*.py")):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        syntax.append(path.name)
    broken_links = []
    for path in HERE.glob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", path.read_text(encoding="utf-8")):
            if target.startswith(("https://", "http://", "#")):
                continue
            if not (path.parent / target.split("#", 1)[0]).exists():
                broken_links.append(dict(file=path.name, target=target))
    issues = set(re.findall(r"^### (P[012]-\d+)",
                            (HERE / "paper_conformance_2026-10-02.md").read_text(encoding="utf-8"), re.M))
    referenced = set(re.findall(r"P[012]-\d+", (HERE / "source_review.md").read_text(encoding="utf-8")))
    probes = read_json("evidence.json")
    hashes = full_hashes() if args.hash_containers else read_json("container_integrity.json")
    result = dict(original_files=len(snapshot), original_file_sizes_checked=len(snapshot),
                  original_small_file_hashes_checked=checked_hashes, changed_original_files=changed,
                  inventory_rows=len(inventory), audit_python_syntax_ok=syntax,
                  broken_report_links=broken_links, issue_groups=len(issues),
                  undefined_issue_references=sorted(referenced - issues),
                  probe_groups=len(probes), completed_probe_groups=sum(x["completed"] for x in probes),
                  recorded_container_hash_checks=len(hashes),
                  all_recorded_container_hashes_match=all(x["body_hash_matches"] and x["no_trailing_bytes"] for x in hashes),
                  containers_rehashed_in_this_run=args.hash_containers)
    if args.hash_containers:
        result["container_hashes"] = hashes
    result["audit_validation_ok"] = (not changed and not broken_links and not (referenced - issues)
                                      and all(x["completed"] for x in probes)
                                      and result["all_recorded_container_hashes_match"])
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False))
    return int(not result["audit_validation_ok"])


if __name__ == "__main__":
    raise SystemExit(main())
