"""Verify an Our Notes master-data dump and package its JSON files as a ZIP."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import zipfile
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump_dir", type=Path)
    parser.add_argument("archive", type=Path)
    args = parser.parse_args()

    manifest_path = args.dump_dir / "_dump_manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    members = {"_dump_manifest.json": manifest_bytes}
    for item in manifest["files"]:
        name = item["output"]
        if Path(name).name != name or not name.endswith(".json"):
            raise ValueError(f"Unexpected output path: {name}")
        data = (args.dump_dir / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["output_sha256"]:
            raise ValueError(f"Output hash mismatch: {name}")
        if len(json.loads(data)["_allData"]) != item["records"]:
            raise ValueError(f"Record count mismatch: {name}")
        members[name] = data

    if len(members) != len(manifest["files"]) + 1:
        raise ValueError("Duplicate output names")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name in sorted(members):
            info = zipfile.ZipInfo(name, (2026, 9, 26, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, members[name], compresslevel=9)
    archive_bytes = stream.getvalue()
    if args.archive.exists() and args.archive.read_bytes() != archive_bytes:
        with zipfile.ZipFile(args.archive) as prior:
            if set(prior.namelist()) != set(members) or any(
                prior.read(name) != data for name, data in members.items()
            ):
                raise FileExistsError(f"Refusing to overwrite an archive with different content: {args.archive}")
    args.archive.parent.mkdir(parents=True, exist_ok=True)
    args.archive.write_bytes(archive_bytes)
    print(f"{len(members)} members; {len(archive_bytes)} bytes; SHA-256 {hashlib.sha256(archive_bytes).hexdigest()}")
    print(args.archive.resolve())


if __name__ == "__main__":
    main()
