#!/usr/bin/env python3
import csv
import hashlib
import sys
import os
import subprocess

# --- SETTINGS ---
# This script runs under src/processing.
# Data should be written to data/processed_csvs.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(os.path.dirname(SCRIPT_DIR)) # src -> tls-project
DATA_DIR = os.path.join(PROJECT_ROOT, 'data', 'processed_csvs')

# Master file path (Default if not provided by watcher)
MASTER_JA3_FILE = os.path.join(DATA_DIR, 'master_ja3_results.csv')

def md5hex(s: str) -> str:
    """Returns the MD5 hash of the given string in hex."""
    return hashlib.md5(s.encode()).hexdigest()

def normalize_list_field(field):
    """Converts TShark list format ('4865,49195') to JA3 format ('4865-49195')."""
    if field is None:
        return ""
    field = field.strip().strip("[]")
    if not field:
        return ""
    parts = []
    # TShark sometimes uses commas, sometimes semicolons
    for token in field.replace(";", ",").split(","):
        tok = token.strip()
        if not tok:
            continue
        if tok.lower().startswith("0x"):
            try:
                parts.append(str(int(tok, 16)))
            except ValueError:
                parts.append(tok)
        else:
            parts.append(tok)
    return "-".join(parts)

def build_ja3_string(row):
    """Generates the JA3 string from a CSV row (dict)."""
    version = row.get('tls.handshake.version') or row.get('ssl.handshake.version') or ''
    
    # Ciphers
    ciphers = normalize_list_field(
        row.get('tls.handshake.ciphersuites') or row.get('ssl.handshake.ciphersuites')
    )
    
    # Extensions (Exclude: 13=signature_algorithms, 65281=renegotiation_info, etc. per JA3 spec)
    # Extensions must be ordered and separated by '-' in JA3 standard.
    # TShark outputs extension types comma-separated.
    ext_str = row.get('tls.handshake.extension.type') or row.get('ssl.handshake.extension.type')
    extensions_list = []
    if ext_str:
        for x in ext_str.split(','):
            x = int(x.strip()) if x.strip().isdigit() else x
            # JA3 spec: exclude 0x000d (13) and 0xff01 (65281)
            # Note: TShark usually gives decimal values.
            if x not in [13, 65281]: 
                extensions_list.append(str(x))
    extensions = "-".join(extensions_list)

    # Elliptic Curves (Supported Groups)
    groups = normalize_list_field(
        row.get('tls.handshake.extensions_supported_group') or row.get('ssl.handshake.extensions_supported_group')
    )
    
    # Elliptic Curve Point Formats
    ec_formats = normalize_list_field(
        row.get('tls.handshake.extensions_ec_point_format') or row.get('ssl.handshake.extensions_ec_point_format')
    )

    # JA3 String: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
    # Example decimal version: 771 (TLS 1.2)
    try:
        ver_int = int(version, 16) if version.startswith('0x') else int(version)
    except:
        ver_int = 771 # Default fallback

    ja3_str = f"{ver_int},{ciphers},{extensions},{groups},{ec_formats}"
    return ja3_str

def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_ja3.py <input_pcap> <output_csv>", file=sys.stderr)
        sys.exit(1)

    pcap_file = sys.argv[1]
    output_csv = sys.argv[2]
    
    # TShark command: Extract only Client Hello packets
    # Fields: IP src/dst, Port src/dst, TLS version, Ciphers, Extensions, Groups, EC Formats
    tshark_cmd = [
        'tshark', '-r', pcap_file,
        '-Y', 'ssl.handshake.type==1 or tls.handshake.type==1',
        '-T', 'fields', '-E', 'header=y', '-E', 'separator=,', '-E', 'quote=d', '-E', 'occurrence=a',
        '-e', 'frame.time_epoch',
        '-e', 'ip.src', '-e', 'ip.dst',
        '-e', 'tcp.srcport', '-e', 'tcp.dstport',
        '-e', 'tls.handshake.version',
        '-e', 'tls.handshake.ciphersuites',
        '-e', 'tls.handshake.extension.type',
        '-e', 'tls.handshake.extensions_supported_group',
        '-e', 'tls.handshake.extensions_ec_point_format'
    ]

    try:
        # Run TShark and capture output
        result = subprocess.run(tshark_cmd, capture_output=True, text=True, encoding='utf-8')
        if result.returncode != 0:
            print(f"ERROR: Error running TShark: {result.stderr}", file=sys.stderr)
            sys.exit(1)
        
        lines = result.stdout.splitlines()
        if len(lines) < 2:
            # Header exists but no data
            print(f"WARNING: {pcap_file} - No ClientHello found.", file=sys.stderr)
            # Exit to avoid creating empty files (Watcher handles missing files gracefully).
            sys.exit(0)

        # CSV Reader (Parse TShark output)
        reader = csv.DictReader(lines)
        
        # Output data
        processed_rows = []
        ja3_rows = []

        for row in reader:
            # Calculate JA3
            ja3_full = build_ja3_string(row)
            ja3_hash = md5hex(ja3_full)
            
            # --- 1. Raw Data Output (For Raw CSV) ---
            # Add ja3 to current row and append to list (watcher will add this to raw csv)
            row['ja3'] = ja3_full
            row['ja3_md5'] = ja3_hash
            processed_rows.append(row)
            
            # --- 2. Data for Master JA3 Summary ---
            ja3_rows.append({
                'time': row.get('frame.time_epoch'),
                'src': row.get('ip.src'),
                'dst': row.get('ip.dst'),
                'sport': row.get('tcp.srcport'),
                'dport': row.get('tcp.dstport'),
                'ja3': ja3_full,
                'ja3_md5': ja3_hash
            })

        # --- Write Temporary Raw File (Watcher will consume and delete) ---
        if processed_rows:
            with open(output_csv, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=reader.fieldnames + ['ja3', 'ja3_md5'])
                writer.writeheader()
                writer.writerows(processed_rows)

        # --- Append to Master JA3 File ---
        # Done inside Python to avoid opening/closing file repeatedly
        if ja3_rows:
            file_exists = os.path.exists(MASTER_JA3_FILE)
            write_header = not file_exists or os.path.getsize(MASTER_JA3_FILE) == 0
            
            try:
                with open(MASTER_JA3_FILE, 'a', newline='', encoding='utf-8') as f:
                    fields = ['time','src','dst','sport','dport','ja3','ja3_md5']
                    writer = csv.DictWriter(f, fieldnames=fields)
                    if write_header:
                        writer.writeheader()
                    writer.writerows(ja3_rows)
                print(f"Success: {len(ja3_rows)} rows added to Master JA3 file.")
            except Exception as e:
                print(f"ERROR: Issue writing to master file: {e}", file=sys.stderr)

    except Exception as e:
        print(f"CRITICAL ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()