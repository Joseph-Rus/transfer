"""
entropy_firewall.py
-------------------
Module for inspecting byte payloads for high-entropy
(likely encrypted or obfuscated) content.

Shannon entropy reference:
    - Plain English text:    ~3.5 - 4.5 bits/byte
    - Compressed data:       ~7.0 - 7.5 bits/byte
    - Encrypted / random:    ~7.8 - 8.0 bits/byte
"""

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """
    Compute Shannon entropy of a byte sequence.
    Returns bits per byte (0.0 - 8.0).
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
    Return the maximum Shannon entropy found across all windows.
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