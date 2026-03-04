```
#!/usr/bin/env python3
"""
test_listener.py
----------------
TCP server that accepts connections, reads payloads, and runs entropy
analysis on each one. Logs whether each payload would be blocked or allowed.

Usage:
    python3 test_listener.py [--port 9000] [--threshold 7.2]
"""

import socket
import sys
import threading

from entropy_firewall import sliding_window_entropy

THRESHOLD = 7.2
HOST = "0.0.0.0"
PORT = 9000
WINDOW = 256
STEP = 64
BUFFER_SIZE = 65536


def handle_client(conn, addr, threshold):
    try:
        payload = b""
        while True:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            payload += chunk

        if not payload:
            return

        entropy = sliding_window_entropy(payload, window=WINDOW, step=STEP)
        blocked = entropy >= threshold
        status = "BLOCKED" if blocked else "ALLOWED"

        print(f"  [{status}]  {addr[0]}:{addr[1]}  |  "
              f"entropy={entropy:.4f}  |  {len(payload)} bytes  |  "
              f"hex={payload[:32].hex()}")

        response = f"{status} entropy={entropy:.4f}\n".encode()
        conn.sendall(response)
    finally:
        conn.close()


def main():
    threshold = THRESHOLD
    port = PORT

    for i, arg in enumerate(sys.argv[1:], 1):
        if arg == "--port" and i < len(sys.argv) - 1:
            port = int(sys.argv[i + 1])
        if arg == "--threshold" and i < len(sys.argv) - 1:
            threshold = float(sys.argv[i + 1])

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, port))
    server.listen(5)

    print(f"Entropy firewall listening on {HOST}:{port}")
    print(f"Threshold: {threshold} bits/byte  |  Window: {WINDOW}B  |  Step: {STEP}B")
    print(f"Waiting for connections...\n")

    try:
        while True:
            conn, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr, threshold))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        server.close()


if __name__ == "__main__":
    main()
```