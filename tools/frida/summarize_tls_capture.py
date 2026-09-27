"""Summarize TLS ClientHello hosts without exporting packet payloads or tokens."""

import argparse
import csv
import subprocess
from collections import defaultdict
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    args = parser.parse_args()
    completed = subprocess.run(
        [args.tshark, "-r", str(args.pcap), "-Y", "tls.handshake.type == 1",
         "-T", "fields", "-e", "frame.time_relative", "-e", "ip.dst",
         "-e", "tcp.dstport", "-e", "tls.handshake.extensions_server_name",
         "-e", "tls.handshake.extensions_alpn_str"],
        check=True, capture_output=True, text=True,
    )
    grouped = defaultdict(list)
    for line in completed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 5:
            raise ValueError(f"Unexpected tshark row: {line!r}")
        time, ip, port, host, alpn = fields
        grouped[(host, ip, port, alpn)].append(float(time))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as stream:
        writer = csv.writer(stream, delimiter="\t")
        writer.writerow(("sni", "destination_ip", "port", "offered_alpn",
                         "first_seconds", "last_seconds", "client_hellos"))
        for (host, ip, port, alpn), times in sorted(grouped.items(), key=lambda x: min(x[1])):
            writer.writerow((host, ip, port, alpn, f"{min(times):.3f}",
                             f"{max(times):.3f}", len(times)))
    print(f"{len(grouped)} TLS destination/SNI/ALPN groups; {sum(map(len, grouped.values()))} ClientHello packets")
    print(args.output.resolve())


if __name__ == "__main__":
    main()
