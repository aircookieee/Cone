"""Extract readable v39 string literals from a repaired metadata file."""

from __future__ import annotations

import argparse
import base64
import json
import struct
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("metadata", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = args.metadata.read_bytes()
    table_offset, table_size, table_count = struct.unpack_from("<III", data, 8)
    body_offset, body_size, _ = struct.unpack_from("<III", data, 20)
    if table_size != table_count * 4 or body_offset + body_size > len(data):
        raise ValueError("Invalid string literal sections")
    offsets = struct.unpack_from(f"<{table_count}I", data, table_offset)
    valid = 0
    invalid = 0
    long_base64 = 0
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as stream:
        for index, (start, end) in enumerate(zip(offsets, offsets[1:])):
            if start > end or end > body_size:
                invalid += 1
                continue
            raw = data[body_offset + start : body_offset + end]
            try:
                value = raw.decode("utf-8")
            except UnicodeDecodeError:
                invalid += 1
                continue
            is_base64 = False
            if len(value) >= 100 and len(value) % 4 == 0:
                try:
                    base64.b64decode(value, validate=True)
                    is_base64 = True
                    long_base64 += 1
                except ValueError:
                    pass
            stream.write(json.dumps({"index": index, "value": value, "base64": is_base64}, ensure_ascii=False) + "\n")
            valid += 1
    print(f"valid literals: {valid}")
    print(f"skipped/corrupt literals: {invalid}")
    print(f"long base64 candidates: {long_base64}")
    print(args.output)


if __name__ == "__main__":
    main()
