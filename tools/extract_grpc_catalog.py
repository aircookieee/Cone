"""Build a symbolic gRPC service catalog from MetadataExplorer TSV output."""

from __future__ import annotations

import argparse
import csv
import re
import struct
from collections import defaultdict
from pathlib import Path


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index_dir", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--metadata", type=Path, help="Repaired metadata for full service name literals")
    args = parser.parse_args()
    types = read_tsv(args.index_dir / "game_types.tsv")
    methods = read_tsv(args.index_dir / "game_methods.tsv")

    service_names = {
        row["type"]: row["namespace"]
        for row in types
        if row["image"] == "App.Protobuf.dll" and row["type"].endswith("Service")
    }
    routes: dict[str, set[str]] = defaultdict(set)
    for row in methods:
        if row["image"] != "App.Protobuf.dll":
            continue
        base = row["type"]
        rpc = row["method"]
        if not base.endswith("ServiceBase") or rpc == ".ctor" or rpc.startswith("<"):
            continue
        routes[base.removesuffix("Base")].add(rpc)

    wire_names: dict[str, str] = {}
    if args.metadata:
        data = args.metadata.read_bytes()
        literal_offset, literal_size, _ = struct.unpack_from("<III", data, 8 + 12)
        literal_data = data[literal_offset : literal_offset + literal_size]
        for match in re.finditer(rb"app\.[a-z0-9]+\.[A-Za-z0-9]+Service", literal_data):
            full_name = match.group().decode("ascii")
            wire_names[full_name.rsplit(".", 1)[-1]] = full_name

    args.output_dir.mkdir(parents=True, exist_ok=True)
    tsv_path = args.output_dir / "grpc_routes.tsv"
    with tsv_path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(("managed_namespace", "service", "rpc", "wire_service_literal", "candidate_grpc_path"))
        for service in sorted(routes):
            for rpc in sorted(routes[service]):
                wire_name = wire_names.get(service, "")
                writer.writerow((
                    service_names.get(service, ""), service, rpc, wire_name,
                    f"/{wire_name}/{rpc}" if wire_name else "",
                ))

    md_path = args.output_dir / "grpc_catalog.md"
    with md_path.open("w", encoding="utf-8") as stream:
        stream.write("# Our Notes gRPC service catalog\n\n")
        stream.write("Generated from IL2CPP metadata. These are symbolic service and RPC names; ")
        stream.write("service name literals are read from the metadata when available. ")
        stream.write("Constructed gRPC paths and message fields still need packet validation.\n\n")
        stream.write(f"{len(routes)} services, {sum(map(len, routes.values()))} distinct RPC names.\n\n")
        stream.write(f"Full service name literals found for {sum(service in wire_names for service in routes)} services.\n\n")
        stream.write("| Namespace | Service | RPCs | Wire service literal |\n|---|---|---:|---|\n")
        for service in sorted(routes):
            stream.write(f"| {service_names.get(service, '')} | {service} | {len(routes[service])} | {wire_names.get(service, '')} |\n")
    print(f"services: {len(routes)}")
    print(f"RPCs: {sum(map(len, routes.values()))}")
    print(tsv_path)
    print(md_path)


if __name__ == "__main__":
    main()
