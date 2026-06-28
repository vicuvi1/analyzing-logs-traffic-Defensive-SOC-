#!/usr/bin/env python3
"""
Send test syslog datagrams to the live listener.

Usage:
    python tools/send_test_syslog.py --host 127.0.0.1 --port 5514
    python tools/send_test_syslog.py --host 127.0.0.1 --port 514 --sample samples/syslog_sample.log
"""

from __future__ import annotations

import argparse
import socket
import time
from pathlib import Path


def send_datagram(host: str, port: int, message: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(message.encode("utf-8"), (host, port))
    finally:
        sock.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Send test syslog UDP datagrams")
    parser.add_argument("--host", default="127.0.0.1", help="Target host")
    parser.add_argument("--port", type=int, default=5514, help="Target UDP port")
    parser.add_argument(
        "--sample",
        type=Path,
        help="Send lines from a sample log file",
    )
    parser.add_argument("--interval", type=float, default=0.5, help="Seconds between messages")
    args = parser.parse_args()

    if args.sample and args.sample.exists():
        lines = args.sample.read_text(encoding="utf-8").splitlines()
    else:
        lines = [
            "Mar 15 08:02:15 server sshd[4522]: Failed password for invalid user admin from 203.0.113.77 port 54321 ssh2",
            "Mar 15 08:02:17 server sshd[4523]: Failed password for invalid user root from 203.0.113.77 port 54322 ssh2",
            '<34>1 2024-03-15T08:05:00Z webserver app - - - Suspicious request to /../../../etc/passwd from 198.51.100.22',
        ]

    print(f"Sending {len(lines)} datagram(s) to {args.host}:{args.port} …")
    for line in lines:
        if not line.strip():
            continue
        send_datagram(args.host, args.port, line.strip())
        print(f"  -> {line[:80]}")
        time.sleep(args.interval)

    print("Done.")


if __name__ == "__main__":
    main()
