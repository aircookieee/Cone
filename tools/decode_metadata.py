"""Repair known Our Notes 1.0.1 IL2CPP metadata obfuscation into a copy.

The first eight bytes are a custom marker. Bytes 8..0xfff and bytes
0x1000..0x4fff of each later 0x10000-byte region use XOR 0x66. The first
0x1000..0x4fff region remains opaque, and the trailing partial window from
0x1e15000 to EOF needs an additional XOR. Use finalize_metadata.py and the
captured runtime image to make the complete parser-ready file.
No source file is modified.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


MAGIC = 0xFAB11BAF
XOR_KEY = 0x66
HEADER_SIZE = 0x17C
WINDOW_SIZE = 0x10000
XOR_START = 0x1000
XOR_END = 0x5000
IMAGE_SECTION_INDEX = 20
IMAGE_RECORD_SIZE = 36


def xor_span(data: bytearray, start: int, end: int) -> None:
    data[start:end] = bytes(value ^ XOR_KEY for value in data[start:end])


def decode(source: Path, destination: Path, version: int) -> None:
    raw = source.read_bytes()
    if len(raw) < 0x1000:
        raise ValueError("Input is too small to contain the expected metadata")

    decoded = bytearray(raw)
    xor_span(decoded, 8, 0x1000)
    repaired_windows = 0
    for base in range(WINDOW_SIZE, len(decoded), WINDOW_SIZE):
        start = base + XOR_START
        end = min(base + XOR_END, len(decoded))
        if start >= len(decoded):
            break
        xor_span(decoded, start, end)
        repaired_windows += 1
    struct.pack_into("<II", decoded, 0, MAGIC, version)

    first_offset, first_size, first_count = struct.unpack_from("<III", decoded, 8)
    if first_offset != HEADER_SIZE or first_size != first_count * 4:
        raise ValueError("Decoded v39 header has an invalid string literal index table")

    image_offset, image_size, image_count = struct.unpack_from(
        "<III", decoded, 8 + IMAGE_SECTION_INDEX * 12
    )
    if image_size != image_count * IMAGE_RECORD_SIZE or image_offset + image_size > len(decoded):
        raise ValueError("Decoded image definition section is invalid")
    for index in range(image_count):
        assembly_index = struct.unpack_from("<I", decoded, image_offset + index * IMAGE_RECORD_SIZE + 4)[0]
        if assembly_index != index:
            raise ValueError(f"Image definition {index} failed validation")

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(decoded)
    print(f"source: {source}")
    print(f"source sha256: {hashlib.sha256(raw).hexdigest()}")
    print(f"output: {destination}")
    print(f"output sha256: {hashlib.sha256(decoded).hexdigest()}")
    print(f"metadata version candidate: {version}")
    print(f"XOR windows: {repaired_windows}; images validated: {image_count}")
    print("unresolved: 0x1000..0x4fff and trailing partial window 0x1e15000..EOF")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--version", type=int, default=39)
    args = parser.parse_args()
    decode(args.source, args.destination, args.version)


if __name__ == "__main__":
    main()
