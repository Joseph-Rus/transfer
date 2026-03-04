#!/usr/bin/env python3
"""
entropy_firewall.py
-------------------
Internal firewall script that inspects network traffic payloads for high-entropy
(likely encrypted or obfuscated) byte strings and rejects/blocks them.

Requirements:
    pip install scapy --break-system-packages

Run as root (needed for raw packet capture):
    sudo python3 entropy_firewall.py --iface eth0 --threshold 7.0

How it works:
    1. Sniffs TCP/UDP packets on the specified interface using Scapy.
    2. Extracts the raw payload bytes from each packet.
    3. Slides a window across the payload and computes Shannon entropy for each chunk.
    4. If any chunk (or the overall payload) exceeds the entropy threshold, the
       connection is flagged and optionally blocked via an iptables DROP rule.
    5. All events are logged to stdout and to a rotating log file.

Shannon entropy reference:
    - Plain English text:    ~3.5 – 4.5 bits/byte
    - Compressed data:       ~7.0 – 7.5 bits/byte
    - Encrypted / random:    ~7.8 – 8.0 bits/byte
    Default threshold of 7.2 catches most encrypted payloads while avoiding
    false positives from compressed-but-legitimate traffic (e.g. gzip HTTP).
    Tune with --threshold as needed for your environment.
"""

import argparse
import logging
import math
import os
import subprocess
import sys
import time
from collections import Counter
from logging.handlers import RotatingFileHandler

# ---------------------------------------------------------------------------
# Dependency check
# ---------------------------------------------------------------------------
try:
    from scapy.all import IP, TCP, UDP, Raw, sniff
except ImportError:
    print("[ERROR] Scapy is not installed. Run:  pip install scapy --break-system-packages")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------
def setup_logger(log_file: str = "entropy_firewall.log") -> logging.Logger:
    logger = logging.getLogger("EntropyFirewall")
    logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    # Rotating file handler (5 MB × 3 backups)
    fh = RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=3)
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    logger.addHandler(ch)
    logger.addHandler(fh)
    return logger


logger = setup_logger()


# ---------------------------------------------------------------------------
# Core entropy functions
# ---------------------------------------------------------------------------
def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.
    Returns bits per byte (0.0 – 8.0).
    """
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def sliding_window_entropy(data: bytes, window: int = 256, step: int = 64) -> float:
    """
    Return the *maximum* Shannon entropy found across all windows.
    Using the max rather than the mean makes it harder for an attacker
    to hide encrypted chunks inside largely-plain payloads.
    """
    if len(data) <= window:
        return shannon_entropy(data)

    max_entropy = 0.0
    for i in range(0, len(data) - window + 1, step):
        chunk = data[i : i + window]
        e = shannon_entropy(chunk)
        if e > max_entropy:
            max_entropy = e
    return max_entropy


# ---------------------------------------------------------------------------
# Block / allow helpers
# ---------------------------------------------------------------------------
# Track IPs we've already blocked so we don't issue duplicate iptables calls.
_blocked_ips: set = set()


def block_ip(ip: str, dry_run: bool = False) -> None:
    """Insert an iptables DROP rule for the given source IP."""
    if ip in _blocked_ips:
        return
    _blocked_ips.add(ip)
    rule = f"iptables -I INPUT -s {ip} -j DROP"
    if dry_run:
        logger.warning(f"[DRY-RUN] Would execute: {rule}")
    else:
        try:
            subprocess.run(rule.split(), check=True, capture_output=True)
            logger.warning(f"[BLOCKED] iptables rule added: DROP src {ip}")
        except subprocess.CalledProcessError as exc:
            logger.error(f"[BLOCK FAILED] {exc.stderr.decode().strip()}")


# ---------------------------------------------------------------------------
# Packet inspection callback
# ---------------------------------------------------------------------------
def make_packet_handler(threshold: float, window: int, step: int,
                         block: bool, dry_run: bool, min_payload: int):
    """
    Returns a Scapy packet handler closure configured with the given parameters.
    """
    stats = {"inspected": 0, "flagged": 0, "blocked_connections": 0}
    last_report = [time.time()]

    def handle_packet(pkt):
        # Only care about packets that carry a raw payload
        if not pkt.haslayer(Raw):
            return

        payload: bytes = bytes(pkt[Raw].load)

        # Skip payloads that are too small – entropy of tiny buffers is unreliable
        if len(payload) < min_payload:
            return

        stats["inspected"] += 1

        # Extract addressing info for logging / blocking
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "unknown"

        if pkt.haslayer(TCP):
            proto = "TCP"
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif pkt.haslayer(UDP):
            proto = "UDP"
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
        else:
            proto = "OTHER"
            src_port = dst_port = 0

        # Compute entropy
        entropy = sliding_window_entropy(payload, window=window, step=step)

        logger.debug(
            f"[INSPECT] {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
            f"payload={len(payload)}B | entropy={entropy:.4f}"
        )

        if entropy >= threshold:
            stats["flagged"] += 1
            logger.warning(
                f"[HIGH ENTROPY] {proto} {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                f"entropy={entropy:.4f} (threshold={threshold}) | payload={len(payload)}B"
            )
            # Log first 64 bytes as hex for forensic review
            hex_preview = payload[:64].hex()
            logger.warning(f"  Payload preview (hex): {hex_preview}")

            if block and src_ip != "unknown":
                stats["blocked_connections"] += 1
                block_ip(src_ip, dry_run=dry_run)

        # Periodic stats summary (every 60 s)
        now = time.time()
        if now - last_report[0] >= 60:
            logger.info(
                f"[STATS] inspected={stats['inspected']} | "
                f"flagged={stats['flagged']} | "
                f"blocked={stats['blocked_connections']}"
            )
            last_report[0] = now

    return handle_packet


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Internal entropy-based firewall — detects and optionally blocks high-entropy (encrypted) traffic."
    )
    parser.add_argument(
        "--iface", "-i",
        default=None,
        help="Network interface to sniff on (e.g. eth0, ens3). Defaults to Scapy's default."
    )
    parser.add_argument(
        "--threshold", "-t",
        type=float,
        default=7.2,
        help=(
            "Shannon entropy threshold (bits/byte, 0–8). "
            "Payloads with max-window entropy ≥ this value are flagged. "
            "Default: 7.2  (catches most encrypted traffic; tune down to ~6.8 to be more aggressive)"
        )
    )
    parser.add_argument(
        "--window", "-w",
        type=int,
        default=256,
        help="Sliding window size in bytes for entropy calculation. Default: 256"
    )
    parser.add_argument(
        "--step", "-s",
        type=int,
        default=64,
        help="Step size for the sliding window. Default: 64"
    )
    parser.add_argument(
        "--min-payload", "-m",
        type=int,
        default=64,
        help="Minimum payload size (bytes) to inspect. Smaller packets are skipped. Default: 64"
    )
    parser.add_argument(
        "--block", "-b",
        action="store_true",
        default=False,
        help="If set, automatically add iptables DROP rules for flagged source IPs."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=False,
        help="Log what iptables commands would run but do not execute them."
    )
    parser.add_argument(
        "--filter", "-f",
        type=str,
        default="tcp or udp",
        help='BPF filter string passed to Scapy sniff(). Default: "tcp or udp"'
    )
    parser.add_argument(
        "--log-file",
        type=str,
        default="entropy_firewall.log",
        help="Path to the rotating log file. Default: entropy_firewall.log"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Re-configure logger with the user-supplied log file path
    global logger
    logger = setup_logger(args.log_file)

    if args.block and os.geteuid() != 0:
        logger.error("--block requires root privileges (sudo). Exiting.")
        sys.exit(1)

    logger.info("=" * 60)
    logger.info("Entropy Firewall starting")
    logger.info(f"  Interface  : {args.iface or 'default'}")
    logger.info(f"  BPF filter : {args.filter}")
    logger.info(f"  Threshold  : {args.threshold} bits/byte")
    logger.info(f"  Window     : {args.window} bytes (step={args.step})")
    logger.info(f"  Min payload: {args.min_payload} bytes")
    logger.info(f"  Block mode : {'YES (dry-run)' if args.dry_run else 'YES' if args.block else 'NO (log only)'}")
    logger.info(f"  Log file   : {args.log_file}")
    logger.info("=" * 60)

    handler = make_packet_handler(
        threshold=args.threshold,
        window=args.window,
        step=args.step,
        block=args.block,
        dry_run=args.dry_run,
        min_payload=args.min_payload,
    )

    try:
        sniff(
            iface=args.iface,
            filter=args.filter,
            prn=handler,
            store=False,   # Don't buffer packets in memory
        )
    except KeyboardInterrupt:
        logger.info("Shutting down — KeyboardInterrupt received.")
    except PermissionError:
        logger.error("Permission denied. Run with sudo or as root.")
        sys.exit(1)


if __name__ == "__main__":
    main()
