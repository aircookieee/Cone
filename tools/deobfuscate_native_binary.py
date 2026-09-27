"""Restore protected Our Notes arm64 ELF sections into a separate analysis copy.

The first protected 16 KB window of each section is taken from the native
process. Later windows are XOR 0x98 over file offsets 0xc000..0xffff of each
0x10000-byte block, plus the final partial block after the last full window.
ELF relocation entries and original package files are not modified. This
script is deliberately specific to the hash-checked 1.0.1 ELF.
"""

from __future__ import annotations

import argparse
import hashlib
import mmap
import shutil
import struct
from pathlib import Path


SOURCE_SHA256 = "514a5b73d038c264b60cc91fd4a747cf178190c6b2096e6d7007c2020e2b1bca"
WINDOW = 0x10000
MASK_START = 0xC000
MASK = 0x98
SECTIONS = (
    (".rodata", 0x1FFA260, 0xD37574, 0x1FFC000,
     "rodata_first_mask-runtime.bin",
     "8cda0fc954cc1492d38c83e3f1acec7e94d262d6c2f0b0d20eadc82e92c60b7c"),
    ("il2cpp", 0x54C96AC, 0x6920D88, 0x54CC000,
     "il2cpp_first_mask-runtime.bin",
     "18deac63ea28c6ea1b651176a735cfb56923395a9f0e309c3836cf739c345891"),
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def section_headers(data: mmap.mmap) -> dict[str, tuple[int, int]]:
    elf = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    shoff, shentsize, shnum, shstrndx = elf[5], elf[10], elf[11], elf[12]
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize)
                for i in range(shnum)]
    strings = sections[shstrndx]
    names = data[strings[4]:strings[4] + strings[5]]
    return {
        names[section[0]:].split(b"\0", 1)[0].decode(): (section[4], section[5])
        for section in sections
    }


def validate_generic_table(data: mmap.mmap) -> None:
    table_offset = 0x26E2818
    table_count = 345722
    previous = -1
    max_adjustor = -1
    for index, (spec, method, invoker, adjustor) in enumerate(
        struct.iter_unpack("<iiii", data[table_offset:table_offset + table_count * 16])
    ):
        if not (previous <= spec < 424396
                and 0 <= method < 345229
                and (invoker == -1 or 0 <= invoker < 49365)
                and (adjustor == -1 or 0 <= adjustor < 100000)):
            raise ValueError(f"Invalid decoded generic table entry {index}")
        previous = spec
        max_adjustor = max(max_adjustor, adjustor)
    if max_adjustor != 68983:
        raise ValueError(f"Unexpected maximum adjustor index: {max_adjustor}")
    print(f"Generic table: {table_count} entries valid; max adjustor={max_adjustor}")


def deobfuscate(source: Path, spans_dir: Path, destination: Path) -> None:
    if sha256_file(source) != SOURCE_SHA256:
        raise ValueError("Source ELF hash does not match the analyzed 1.0.1 build")
    spans = {}
    for name, offset, size, first, filename, expected_hash in SECTIONS:
        content = (spans_dir / filename).read_bytes()
        if len(content) != 0x4000 or hashlib.sha256(content).hexdigest() != expected_hash:
            raise ValueError(f"Runtime span invalid: {filename}")
        spans[name] = content

    if source.resolve() == destination.resolve():
        raise ValueError("Refusing to overwrite the original ELF")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    with destination.open("r+b") as stream, mmap.mmap(stream.fileno(), 0) as data:
        if data[:4] != b"\x7fELF":
            raise ValueError("Source is not an ELF file")
        headers = section_headers(data)
        for name, offset, size, first, filename, _ in SECTIONS:
            if headers.get(name) != (offset, size):
                raise ValueError(f"Unexpected {name} section layout")
            windows = 0
            for base in range(offset & ~(WINDOW - 1), offset + size, WINDOW):
                start = max(base + MASK_START, offset)
                end = min(base + WINDOW, offset + size)
                if start >= end:
                    continue
                if start == first:
                    if end - start != len(spans[name]):
                        raise ValueError(f"Unexpected first {name} window length")
                    data[start:end] = spans[name]
                else:
                    data[start:end] = bytes(value ^ MASK for value in data[start:end])
                windows += 1
            section_end = offset + size
            tail_start = section_end & ~(WINDOW - 1)
            if tail_start > first and tail_start + MASK_START >= section_end:
                data[tail_start:section_end] = bytes(
                    value ^ MASK for value in data[tail_start:section_end]
                )
                print(f"{name}: restored {windows} windows and "
                      f"0x{section_end - tail_start:x} tail bytes")
            else:
                print(f"{name}: restored {windows} windows")
        validate_generic_table(data)
        data.flush()
    print(f"Source SHA-256: {SOURCE_SHA256}")
    print(f"Output: {destination} ({destination.stat().st_size} bytes)")
    print(f"Output SHA-256: {sha256_file(destination)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("spans_dir", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    deobfuscate(args.source, args.spans_dir, args.destination)


if __name__ == "__main__":
    main()
