#!/usr/bin/env python3
"""
attack_simulation.py
--------------------
Sends simulated attack and legitimate payloads over TCP to
test_listener.py and prints the firewall's verdict for each.

Usage:
    python3 attack_simulation.py [--host 127.0.0.1] [--port 9000]
"""

import base64
import json
import os
import socket
import sys
import time
import zlib

HOST = "127.0.0.1"
PORT = 9000


def send_payload(label, data, description):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((HOST, PORT))
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        response = sock.recv(1024).decode().strip()
        sock.close()
    except Exception as e:
        response = f"ERROR: {e}"

    print(f"  {response}  |  {label}")
    print(f"           {description}")
    print(f"           sent {len(data)} bytes")
    print()


def main():
    global HOST, PORT
    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--host" and i < len(sys.argv) - 1:
            HOST = sys.argv[i + 1]
        if arg == "--port" and i < len(sys.argv) - 1:
            PORT = int(sys.argv[i + 1])

    print()
    print("=" * 65)
    print("LEGITIMATE TRAFFIC (should pass through)")
    print("=" * 65)
    print()

    send_payload(
        "Normal HTTP GET",
        b"GET /api/users?page=2 HTTP/1.1\r\nHost: app.example.com\r\nAccept: application/json\r\n\r\n" * 4,
        "Standard web request",
    )

    send_payload(
        "JSON API response",
        json.dumps({
            "users": [
                {"id": i, "name": f"user_{i}", "email": f"user_{i}@example.com", "role": "member"}
                for i in range(20)
            ]
        }).encode(),
        "Structured JSON data",
    )

    send_payload(
        "HTML page content",
        b"<html><head><title>Dashboard</title></head><body>"
        b"<div class='container'><h1>Welcome back</h1>"
        b"<p>Your account is active. Last login: 2025-03-01.</p>"
        b"</div></body></html>" * 3,
        "Rendered HTML markup",
    )

    send_payload(
        "SQL query batch",
        b"SELECT u.id, u.name, o.total FROM users u JOIN orders o ON u.id = o.user_id WHERE o.date > '2025-01-01' ORDER BY o.total DESC LIMIT 100; " * 4,
        "Database queries",
    )

    print("=" * 65)
    print("ATTACK PAYLOADS (should be blocked)")
    print("=" * 65)
    print()

    send_payload(
        "Attack 1: Encrypted data exfiltration",
        os.urandom(1024),
        "Raw encrypted stolen data",
    )

    send_payload(
        "Attack 2: C2 command channel",
        b"X-Session: " + os.urandom(512),
        "Encrypted commands from C2 server",
    )

    decoy = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>OK</body></html>"
    send_payload(
        "Attack 3: Encrypted payload after HTTP decoy",
        decoy + os.urandom(512),
        "Normal HTTP header hiding encrypted blob",
    )

    send_payload(
        "Attack 4: Ransomware key exchange",
        b"KEY_EXCHANGE|" + os.urandom(512) + b"|END",
        "Encryption key sent to attacker",
    )

    print("=" * 65)
    print("EVASION TECHNIQUES")
    print("=" * 65)
    print()

    send_payload(
        "Evasion 1: Base64 wrapping",
        b"data=" + base64.b64encode(os.urandom(512)),
        "Encoding drops entropy from ~7.5 to ~5.9",
    )

    send_payload(
        "Evasion 2: Hex encoding",
        os.urandom(256).hex().encode(),
        "Hex uses 16 chars, entropy drops to ~4.0",
    )

    padding = b"AAAA" * 200
    send_payload(
        "Evasion 3: Plaintext padding around encrypted core",
        padding + os.urandom(512) + padding,
        "Sliding window should still find the encrypted chunk",
    )

    send_payload(
        "Evasion 4: Single-byte XOR",
        bytes(b ^ 0xAB for b in os.urandom(512)),
        "XOR barely changes entropy distribution",
    )

    words = ["the", "of", "and", "to", "in", "is", "it", "for",
             "was", "on", "are", "as", "with", "his", "they", "at"]
    send_payload(
        "Evasion 5: Steganographic word encoding",
        " ".join(words[b % len(words)] for b in os.urandom(300)).encode(),
        "Encrypted bytes mapped to English words",
    )

    print("=" * 65)
    print("EDGE CASES")
    print("=" * 65)
    print()

    legitimate_html = b"<html>" + b"<p>This is paragraph content for the page.</p>" * 100 + b"</html>"
    send_payload(
        "Gzip-compressed HTML",
        zlib.compress(legitimate_html, level=9),
        "Legitimate compressed transfer",
    )

    send_payload(
        "Log file with encrypted tail",
        b"Normal log entry: user logged in at 10:32 AM\n" * 20 + os.urandom(300),
        "Mostly plain with encrypted chunk at end",
    )

    print("=" * 65)
    print("Done. Check the listener terminal for detailed verdicts.")
    print("=" * 65)


if __name__ == "__main__":
    main()