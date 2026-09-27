"""Cross-check generated protobuf C# signatures against the repaired metadata index.

The C# dump is partial and its native addresses are not trusted. This script only
uses generated managed declarations and checks every field number against metadata.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream, delimiter="\t"))


def write_tsv(path: Path, columns: tuple[str, ...], rows: list[tuple[str, ...]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(columns)
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dump", type=Path)
    parser.add_argument("metadata_index", type=Path)
    parser.add_argument("routes", type=Path)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    dump = args.dump.read_text(encoding="utf-8")
    expected_fields = {
        (row["namespace"], row["type"], row["field_constant"]): row["field_number"]
        for row in read_tsv(args.metadata_index / "protobuf_fields.tsv")
    }
    expected_routes = {(row["service"], row["rpc"]): row for row in read_tsv(args.routes)}

    class_re = re.compile(
        r"^public sealed class (\w+) : IMessage<[^\n]+\n\{(.*?)^\}", re.M | re.S
    )
    base_re = re.compile(
        r"^public abstract class (\w+)\.\1Base\b[^\n]*\n\{(.*?)^\}", re.M | re.S
    )
    namespace_re = re.compile(r"^// Namespace: ([^\n]*)", re.M)
    namespaces = list(namespace_re.finditer(dump))

    def namespace_at(position: int) -> str:
        # C# dump emits a namespace marker before each type, including nested types.
        lo, hi = 0, len(namespaces)
        while lo < hi:
            mid = (lo + hi) // 2
            if namespaces[mid].start() <= position:
                lo = mid + 1
            else:
                hi = mid
        return namespaces[lo - 1].group(1) if lo else ""

    field_rows: list[tuple[str, ...]] = []
    seen_fields: set[tuple[str, str, str]] = set()
    for match in class_re.finditer(dump):
        namespace, type_name, body = namespace_at(match.start()), match.group(1), match.group(2)
        if not namespace.startswith("App.Protobuf."):
            continue
        properties = {
            prop.group(2): prop.group(1)
            for prop in re.finditer(r"^\s*public (?!static)([^\n]+?) (\w+) \{ get;", body, re.M)
        }
        for field in re.finditer(r"^\s*public const int (\w+)FieldNumber = (\d+);", body, re.M):
            property_name, number = field.groups()
            key = (namespace, type_name, property_name + "FieldNumber")
            if expected_fields.get(key) != number:
                raise ValueError(f"Field number differs from metadata: {key}: {number}")
            if property_name not in properties:
                raise ValueError(f"Missing property type: {key}")
            seen_fields.add(key)
            field_rows.append((namespace, type_name, property_name, number, properties[property_name]))

    if seen_fields != expected_fields.keys():
        missing = set(expected_fields) - seen_fields
        raise ValueError(f"Metadata/C# field sets differ: {len(missing)} missing; sample {list(missing)[:3]}")

    signatures: dict[tuple[str, str], tuple[str, str]] = {}
    for match in base_re.finditer(dump):
        service, body = match.group(1), match.group(2)
        for method in re.finditer(
            r"^\s*public virtual Task<([^>]+)> (\w+)\(([^ ]+) request, ServerCallContext context\)",
            body,
            re.M,
        ):
            response, rpc, request = method.groups()
            key = (service, rpc)
            signature = (request, response)
            if key in signatures and signatures[key] != signature:
                raise ValueError(f"Conflicting overloads: {key}")
            signatures[key] = signature

    if signatures.keys() != expected_routes.keys():
        raise ValueError(
            f"Route/signature sets differ: {len(set(expected_routes) - set(signatures))} missing signatures, "
            f"{len(set(signatures) - set(expected_routes))} unexpected"
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_tsv(
        args.output_dir / "protobuf_field_types.tsv",
        ("namespace", "message", "property", "field_number", "csharp_type"),
        sorted(field_rows),
    )
    route_rows = []
    for key, route in sorted(expected_routes.items()):
        request, response = signatures[key]
        route_rows.append((
            route["managed_namespace"], route["service"], route["rpc"],
            request, response, route["wire_service_literal"], route["candidate_grpc_path"],
        ))
    write_tsv(
        args.output_dir / "grpc_signatures.tsv",
        ("managed_namespace", "service", "rpc", "request_type", "response_type", "wire_service_literal", "candidate_grpc_path"),
        route_rows,
    )
    print(f"Verified {len(field_rows)} protobuf fields and {len(route_rows)} RPC signatures")


if __name__ == "__main__":
    main()
