#!/usr/bin/env python3
"""
Simple test for entropy_firewall.py
Run: python3 test_simple.py
"""

import os
from entropy_firewall import shannon_entropy, sliding_window_entropy

THRESHOLD = 7.2

def test(label, data):
    entropy = sliding_window_entropy(data, window=256, step=64)
    result = "BLOCK ❌" if entropy >= THRESHOLD else "ALLOW ✅"
    print(f"  {result}  |  entropy={entropy:.4f}  |  {label}")

print("\n--- Entropy Firewall Quick Test ---\n")

test("Plain text",         b"the quick brown fox jumps over the lazy dog " * 12)
test("HTTP request",       b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n" * 5)
test("JSON payload",       b'{"user": "joey", "action": "login", "status": "ok"}' * 10)
test("Encrypted (random)", os.urandom(512))
test("Mixed (plain+enc)",  b"hello world this is normal text " * 10 + os.urandom(300))

print()
