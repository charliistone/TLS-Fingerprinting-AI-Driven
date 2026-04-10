import csv
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional


TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    # TCP ports (standard HTTPS / TLS over TCP)
    "tcp.srcport",
    "tcp.dstport",
    # UDP ports — populated for QUIC traffic (TLS over UDP: Apple, Google, Cloudflare etc.)
    "udp.srcport",
    "udp.dstport",
    # Transport protocol for tagging (6=TCP, 17=UDP)
    "ip.proto",
    "tls.handshake.version",
    "tls.handshake.ciphersuites",
    "tls.handshake.extension.type",
    "tls.handshake.extensions_supported_group",
    "tls.handshake.extensions_ec_point_format",
]

# RFC 8701 GREASE values — filtered out of JA3 computation
GREASE_VALUES = {
    2570, 6682, 10794, 14906,
    19018, 23130, 27242, 31354,
    35466, 39578, 43690, 47802,
    51914, 56026, 60138, 64250,
}


def resolve_tshark_path(tshark_path: Optional[str] = None) -> str:
    return (
        tshark_path
        or os.environ.get("TSHARK_PATH")
        or shutil.which("tshark")
        or r"C:\Program Files\Wireshark\tshark.exe"
    )


def md5hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def safe_int(value: Optional[str]) -> Optional[int]:
    if value is None:
        return None
    value = str(value).strip()
    if not value:
        return None
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        return None


def normalize_tls_version(value: Optional[str]) -> str:
    parsed = safe_int(value)
    if parsed is None:
        return ""
    return str(parsed)


def parse_list_field(field: Optional[str]) -> List[int]:
    if field is None:
        return []
    field = str(field).strip().strip('"').strip()
    if not field:
        return []
    tokens = field.replace(";", ",").split(",")
    values: List[int] = []
    for token in tokens:
        token = token.strip()
        if not token:
            continue
        parsed = safe_int(token)
        if parsed is not None:
            values.append(parsed)
    return values


def remove_grease(values: List[int]) -> List[int]:
    return [v for v in values if v not in GREASE_VALUES]


def build_ja3_string(row: Dict[str, str]) -> str:
    version = normalize_tls_version(row.get("tls.handshake.version"))
    ciphers = remove_grease(parse_list_field(row.get("tls.handshake.ciphersuites")))
    extensions = remove_grease(parse_list_field(row.get("tls.handshake.extension.type")))
    groups = remove_grease(parse_list_field(row.get("tls.handshake.extensions_supported_group")))
    ec_formats = parse_list_field(row.get("tls.handshake.extensions_ec_point_format"))

    ciphers_str = "-".join(str(v) for v in ciphers)
    extensions_str = "-".join(str(v) for v in extensions)
    groups_str = "-".join(str(v) for v in groups)
    ec_formats_str = "-".join(str(v) for v in ec_formats)

    return f"{version},{ciphers_str},{extensions_str},{groups_str},{ec_formats_str}"


def _build_tshark_command(pcap_file: str, tshark_path: Optional[str] = None) -> List[str]:
    cmd = [
        resolve_tshark_path(tshark_path),
        "-r", pcap_file,
        "-Y", "tls.handshake.type==1",
        "-T", "fields",
        "-E", "header=y",
        "-E", "separator=\t",
        "-E", "quote=d",
        "-E", "occurrence=a",
    ]
    for field in TSHARK_FIELDS:
        cmd.extend(["-e", field])
    return cmd


def extract_client_hello_records(
    pcap_file: str,
    tshark_path: Optional[str] = None
) -> List[Dict[str, object]]:
    pcap_path = Path(pcap_file)
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    cmd = _build_tshark_command(str(pcap_path), tshark_path=tshark_path)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8"
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"TShark failed for {pcap_file}\nSTDERR: {result.stderr.strip()}"
        )

    output = result.stdout.strip()
    if not output:
        return []

    lines = output.splitlines()
    if len(lines) < 2:
        return []

    reader = csv.DictReader(lines, delimiter="\t")
    records: List[Dict[str, object]] = []

    for row in reader:
        ja3_string = build_ja3_string(row)
        if not ja3_string.strip(","):
            continue

        ja3_hash = md5hex(ja3_string)

        # TCP ports take priority; fall back to UDP ports for QUIC traffic
        src_port = safe_int(row.get("tcp.srcport")) or safe_int(row.get("udp.srcport"))
        dst_port = safe_int(row.get("tcp.dstport")) or safe_int(row.get("udp.dstport"))

        # Determine transport: TCP(6), UDP/QUIC(17)
        proto_num = safe_int(row.get("ip.proto"))
        if proto_num == 17:
            transport = "QUIC/UDP"
        elif proto_num == 6:
            transport = "TCP"
        else:
            transport = "Unknown"

        record = {
            "timestamp_epoch": row.get("frame.time_epoch"),
            "src_ip": row.get("ip.src") or None,
            "dst_ip": row.get("ip.dst") or None,
            "src_port": src_port,
            "dst_port": dst_port,
            "transport": transport,
            "tls_version": normalize_tls_version(row.get("tls.handshake.version")),
            "ja3_string": ja3_string,
            "ja3_hash": ja3_hash,
            "raw_metadata": json.dumps(
                {
                    "transport": transport,
                    "tls.handshake.version": row.get("tls.handshake.version"),
                    "tls.handshake.ciphersuites": row.get("tls.handshake.ciphersuites"),
                    "tls.handshake.extension.type": row.get("tls.handshake.extension.type"),
                    "tls.handshake.extensions_supported_group": row.get("tls.handshake.extensions_supported_group"),
                    "tls.handshake.extensions_ec_point_format": row.get("tls.handshake.extensions_ec_point_format"),
                },
                ensure_ascii=False,
            ),
        }
        records.append(record)

    return records


def write_records_to_csv(records: List[Dict[str, object]], output_csv: str) -> None:
    output_path = Path(output_csv)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = [
        "timestamp_epoch", "src_ip", "dst_ip", "src_port", "dst_port",
        "tls_version", "ja3_string", "ja3_hash", "raw_metadata",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(records)


def process_pcap_file(
    pcap_file: str,
    output_csv: Optional[str] = None,
    tshark_path: Optional[str] = None
) -> List[Dict[str, object]]:
    """Extract JA3 records from a PCAP file. Optionally write to CSV.

    Args:
        pcap_file: Path to .pcap or .pcapng file.
        output_csv: Optional path to write extracted records as CSV.
        tshark_path: Optional full path to tshark binary.

    Returns:
        List of extracted record dicts with JA3 hashes and metadata.
    """
    records = extract_client_hello_records(pcap_file, tshark_path=tshark_path)
    if output_csv:
        write_records_to_csv(records, output_csv)
    return records


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Extract TLS ClientHello metadata and JA3 hashes from PCAP"
    )
    parser.add_argument("pcap_file", help="Path to input .pcap or .pcapng file")
    parser.add_argument("--output-csv", dest="output_csv", default=None, help="Optional CSV output path")
    parser.add_argument("--tshark-path", dest="tshark_path", default=None, help="Optional full path to tshark binary")

    args = parser.parse_args()
    extracted = process_pcap_file(args.pcap_file, args.output_csv, args.tshark_path)
    print(json.dumps({
        "pcap_file": os.path.abspath(args.pcap_file),
        "record_count": len(extracted),
        "records": extracted
    }, indent=2, ensure_ascii=False))
