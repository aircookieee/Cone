"""Verify bundled Master/*.bin against the package's MasterManifest.json."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("master_dir", type=Path)
    parser.add_argument("--json-output", type=Path)
    args = parser.parse_args()
    manifest = json.loads((args.master_dir / "MasterManifest.json").read_text(encoding="utf-8"))
    issues = []
    sizes = []
    listed = set()
    for item in manifest["files"]:
        name = item["name"]
        listed.add(name)
        path = args.master_dir / name
        if not path.is_file():
            issues.append(f"missing: {name}")
            continue
        data = path.read_bytes()
        sizes.append(len(data))
        if len(data) != item["size"]:
            issues.append(f"size mismatch: {name}")
        if hashlib.sha256(data).hexdigest().lower() != item["hash"].lower():
            issues.append(f"SHA-256 mismatch: {name}")
    extra = sorted(path.name for path in args.master_dir.glob("*.bin") if path.name not in listed)
    result = {
        "version": manifest["version"],
        "listed_files": len(listed),
        "present_files": len(sizes),
        "total_bytes": sum(sizes),
        "size_mod_16": dict(sorted(Counter(size % 16 for size in sizes).items())),
        "extra_bins": extra,
        "issues": issues,
    }
    if args.json_output:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result, indent=2))
    if issues or extra:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
