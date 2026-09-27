"""Build parser-ready Our Notes metadata from the observed ARM runtime image.

The runtime decrypted the opaque first string-literal index window and the
trailing partial XOR window. Its first eight bytes are runtime state, so this
copy replaces them with standard IL2CPP magic and inferred Unity 6 version 39.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
from pathlib import Path


PARTIAL_SHA256 = "6c057cfc65307445b606eecfcf9a579c2dd91696193855052aae2806dd5b74fd"
RUNTIME_SHA256 = "91aa665bd138276af998b9090f9395ada45ed78bbbc1e51cbb13ed2e61e9ef59"
MAGIC = 0xFAB11BAF
VERSION = 39
OPAQUE_START = 0x1000
OPAQUE_END = 0x5000
TAIL_START = 0x1E15000


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def finalize(partial_path: Path, runtime_path: Path, output_path: Path) -> None:
    partial = partial_path.read_bytes()
    runtime = runtime_path.read_bytes()
    if sha256(partial) != PARTIAL_SHA256:
        raise ValueError("Partial repair hash does not match the analyzed package")
    if sha256(runtime) != RUNTIME_SHA256:
        raise ValueError("Runtime snapshot hash does not match the observed ARM process")
    if len(runtime) != len(partial):
        raise ValueError("Runtime snapshot has the wrong length")
    if runtime[:8] != bytes.fromhex("0000000018000000"):
        raise ValueError("Unexpected runtime header state")
    if runtime[8:OPAQUE_START] != partial[8:OPAQUE_START]:
        raise ValueError("Runtime header differs from the partial repair")
    if runtime[OPAQUE_END:TAIL_START] != partial[OPAQUE_END:TAIL_START]:
        raise ValueError("Runtime body differs outside the known protected windows")
    if bytes(value ^ 0x66 for value in partial[TAIL_START:]) != runtime[TAIL_START:]:
        raise ValueError("Trailing runtime data does not match XOR 0x66")

    output = bytearray(runtime)
    struct.pack_into("<II", output, 0, MAGIC, VERSION)

    table_offset, table_size, table_count = struct.unpack_from("<III", output, 8)
    data_offset, data_size, data_count = struct.unpack_from("<III", output, 20)
    if table_offset != 0x17C or table_size != table_count * 4 or data_count != table_count - 1:
        raise ValueError("Invalid string-literal index section")
    if data_offset + data_size > len(output):
        raise ValueError("String-literal data exceeds the file")
    offsets = struct.unpack_from(f"<{table_count}I", output, table_offset)
    if offsets[0] != 0 or offsets[-1] != data_size:
        raise ValueError("Invalid string-literal offsets")
    if any(start > end for start, end in zip(offsets, offsets[1:])):
        raise ValueError("String-literal offsets are not monotonic")

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(output)
    print(f"output: {output_path}")
    print(f"sha256: {sha256(output)}")
    print(f"string-literal indexes validated: {table_count}")
    print(f"runtime-only recovered spans: {OPAQUE_START:#x}..{OPAQUE_END:#x}, {TAIL_START:#x}..{len(output):#x}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("partial", type=Path)
    parser.add_argument("runtime", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    finalize(args.partial, args.runtime, args.output)


if __name__ == "__main__":
    main()
