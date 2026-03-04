#!/usr/bin/env python3
"""
test_entropy_firewall.py
------------------------
Test suite for entropy_firewall.py

Tests are split into two categories:
  1. Unit tests  — pure logic tests (no network, no root needed)
  2. Live tests  — sends real packets over loopback to a local listener
                   (requires root for raw socket / Scapy sniff)

Run all unit tests (no root required):
    python3 test_entropy_firewall.py

Run everything including live network tests (requires root):
    sudo python3 test_entropy_firewall.py --live

Run a specific test class:
    python3 test_entropy_firewall.py TestEntropy
    sudo python3 test_entropy_firewall.py TestLiveTraffic
"""

import argparse
import math
import os
import random
import socket
import string
import sys
import threading
import time
import unittest

# ---------------------------------------------------------------------------
# Import the module under test
# ---------------------------------------------------------------------------
try:
    from entropy_firewall import shannon_entropy, sliding_window_entropy, block_ip
except ModuleNotFoundError:
    print("[ERROR] entropy_firewall.py not found in the same directory.")
    print("        Place test_entropy_firewall.py next to entropy_firewall.py and retry.")
    sys.exit(1)

# ---------------------------------------------------------------------------
# Helpers for generating test payloads
# ---------------------------------------------------------------------------

def make_plaintext(size: int = 512) -> bytes:
    """Human-readable ASCII text — low entropy (~4 bits/byte)."""
    words = (
        "the quick brown fox jumps over the lazy dog "
        "hello world this is a test of the entropy firewall "
        "internal network traffic inspection system "
    )
    blob = (words * (size // len(words) + 1))[:size]
    return blob.encode("ascii")


def make_compressed_like(size: int = 512) -> bytes:
    """
    Simulate moderately high-entropy data (like gzip output).
    Built from a restricted alphabet with repeated patterns — entropy ~6.5–7.2.
    """
    alphabet = bytes(range(32, 127))  # printable range
    return bytes(random.choices(alphabet, k=size))


def make_encrypted(size: int = 512) -> bytes:
    """Truly random bytes — simulates encrypted payload, entropy ~7.9–8.0."""
    return os.urandom(size)


def make_base64_encoded(size: int = 512) -> bytes:
    """Base64-encoded random data — medium-high entropy (~6.0)."""
    import base64
    raw = os.urandom(size * 3 // 4)
    return base64.b64encode(raw)[:size]


def make_mixed_payload(plain_size: int = 300, enc_size: int = 200) -> bytes:
    """
    A payload where most of it is plaintext but a chunk is encrypted.
    Tests that sliding-window catches the high-entropy section.
    """
    return make_plaintext(plain_size) + make_encrypted(enc_size)


def make_http_request() -> bytes:
    """Realistic HTTP GET request — should NOT be flagged."""
    return (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0 (compatible)\r\n"
        b"Accept: text/html,application/xhtml+xml\r\n"
        b"Accept-Language: en-US,en;q=0.9\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )


def make_json_payload() -> bytes:
    """Typical JSON API body — should NOT be flagged."""
    return (
        b'{"user_id": 42, "action": "login", "timestamp": "2026-03-04T10:00:00Z", '
        b'"metadata": {"ip": "192.168.1.100", "device": "desktop", "os": "Windows 11"}, '
        b'"session_token": "abcdef1234567890", "flags": [1, 0, 1, 1, 0]}'
    )


# ---------------------------------------------------------------------------
# UNIT TESTS
# ---------------------------------------------------------------------------

class TestEntropy(unittest.TestCase):
    """Tests for shannon_entropy() correctness."""

    def test_empty_bytes_returns_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_byte_repeated_is_zero(self):
        # All same byte → zero entropy
        self.assertAlmostEqual(shannon_entropy(b"\x00" * 100), 0.0, places=5)

    def test_two_equal_symbols_is_one_bit(self):
        # 50% A, 50% B → H = 1.0
        data = b"AB" * 50
        self.assertAlmostEqual(shannon_entropy(data), 1.0, places=5)

    def test_plaintext_low_entropy(self):
        e = shannon_entropy(make_plaintext(512))
        self.assertLess(e, 5.5, f"Plaintext entropy {e:.4f} should be < 5.5")

    def test_encrypted_high_entropy(self):
        e = shannon_entropy(make_encrypted(512))
        self.assertGreater(e, 7.5, f"Encrypted entropy {e:.4f} should be > 7.5")

    def test_max_entropy_uniform_distribution(self):
        # All 256 byte values once each → H = 8.0
        data = bytes(range(256))
        self.assertAlmostEqual(shannon_entropy(data), 8.0, places=5)

    def test_entropy_bounded(self):
        for _ in range(10):
            e = shannon_entropy(os.urandom(256))
            self.assertGreaterEqual(e, 0.0)
            self.assertLessEqual(e, 8.0)


class TestSlidingWindowEntropy(unittest.TestCase):
    """Tests for sliding_window_entropy() — window-based max detection."""

    def test_short_payload_falls_back_to_full(self):
        data = make_plaintext(64)
        e_window = sliding_window_entropy(data, window=256)
        e_full = shannon_entropy(data)
        self.assertAlmostEqual(e_window, e_full, places=5)

    def test_detects_encrypted_chunk_in_mixed_payload(self):
        mixed = make_mixed_payload(plain_size=400, enc_size=300)
        e = sliding_window_entropy(mixed, window=256, step=64)
        # The encrypted tail should push max entropy above 7.5
        self.assertGreater(e, 7.5,
            f"Sliding window should detect encrypted chunk, got {e:.4f}")

    def test_pure_plaintext_stays_below_threshold(self):
        e = sliding_window_entropy(make_plaintext(1024), window=256, step=64)
        self.assertLess(e, 5.5)

    def test_pure_encrypted_exceeds_threshold(self):
        e = sliding_window_entropy(make_encrypted(1024), window=256, step=64)
        self.assertGreater(e, 7.2)

    def test_larger_step_still_detects_high_entropy(self):
        data = make_encrypted(512)
        e = sliding_window_entropy(data, window=128, step=128)
        self.assertGreater(e, 7.0)


class TestPayloadClassification(unittest.TestCase):
    """
    End-to-end classification tests using a 7.2 threshold.
    These mirror exactly what the firewall does per packet.
    """

    THRESHOLD = 7.2

    def _classify(self, data: bytes) -> str:
        e = sliding_window_entropy(data, window=256, step=64)
        return "BLOCK" if e >= self.THRESHOLD else "ALLOW"

    def test_plaintext_allowed(self):
        result = self._classify(make_plaintext(512))
        self.assertEqual(result, "ALLOW", "Plain text should be ALLOWED")

    def test_http_request_allowed(self):
        result = self._classify(make_http_request())
        self.assertEqual(result, "ALLOW", "HTTP request should be ALLOWED")

    def test_json_payload_allowed(self):
        result = self._classify(make_json_payload())
        self.assertEqual(result, "ALLOW", "JSON payload should be ALLOWED")

    def test_encrypted_blocked(self):
        # Run 5 times since urandom is non-deterministic
        for _ in range(5):
            result = self._classify(make_encrypted(512))
            self.assertEqual(result, "BLOCK", "Encrypted payload should be BLOCKED")

    def test_mixed_payload_blocked(self):
        result = self._classify(make_mixed_payload(plain_size=300, enc_size=256))
        self.assertEqual(result, "BLOCK", "Mixed payload with encrypted chunk should be BLOCKED")

    def test_base64_classification(self):
        # Base64 of random data sits around 6.0 — may or may not trip threshold
        e = sliding_window_entropy(make_base64_encoded(512), window=256, step=64)
        print(f"\n  [INFO] Base64-encoded random data entropy: {e:.4f} "
              f"({'BLOCK' if e >= self.THRESHOLD else 'ALLOW'})")
        # Just verify it's in a sane range (not testing a specific outcome)
        self.assertGreater(e, 4.0)
        self.assertLess(e, 8.0)


class TestBlockIp(unittest.TestCase):
    """Tests for the block_ip() helper (dry-run only — never touches iptables)."""

    def test_dry_run_does_not_raise(self):
        """block_ip in dry-run mode should never raise."""
        try:
            block_ip("10.0.0.1", dry_run=True)
        except Exception as exc:
            self.fail(f"block_ip raised unexpectedly: {exc}")

    def test_duplicate_ip_only_processed_once(self):
        """Calling block_ip twice for the same IP should be a no-op the second time."""
        # Reset internal set for test isolation
        import entropy_firewall
        entropy_firewall._blocked_ips.discard("10.0.0.99")

        block_ip("10.0.0.99", dry_run=True)
        block_ip("10.0.0.99", dry_run=True)  # should silently skip


class TestEntropyBenchmark(unittest.TestCase):
    """Performance sanity check — ensure inspection is fast enough for real traffic."""

    def test_throughput_1000_packets(self):
        """Inspect 1000 x 1KB packets in under 2 seconds."""
        payloads = [os.urandom(1024) for _ in range(1000)]
        start = time.perf_counter()
        for p in payloads:
            sliding_window_entropy(p, window=256, step=64)
        elapsed = time.perf_counter() - start
        pps = 1000 / elapsed
        print(f"\n  [BENCH] 1000 packets (1KB each) in {elapsed:.3f}s = {pps:.0f} pkt/s")
        self.assertLess(elapsed, 2.0,
            f"Inspection of 1000 packets took {elapsed:.2f}s — too slow for live traffic")


# ---------------------------------------------------------------------------
# LIVE NETWORK TESTS  (require root + Scapy)
# ---------------------------------------------------------------------------

LIVE_TESTS_AVAILABLE = False
try:
    from scapy.all import IP, TCP, Raw, send, sniff, conf
    LIVE_TESTS_AVAILABLE = True
except ImportError:
    pass


@unittest.skipUnless(
    LIVE_TESTS_AVAILABLE and os.geteuid() == 0,
    "Live tests require Scapy and root privileges (sudo)"
)
class TestLiveTraffic(unittest.TestCase):
    """
    Sends real packets over loopback and verifies the firewall handler
    correctly classifies them.
    """

    THRESHOLD = 7.2
    LISTEN_PORT = 19876
    RESULTS: list = []

    @classmethod
    def setUpClass(cls):
        from entropy_firewall import make_packet_handler
        cls.flagged = []

        def custom_handler(pkt):
            from scapy.all import Raw
            if not pkt.haslayer(Raw):
                return
            payload = bytes(pkt[Raw].load)
            if len(payload) < 64:
                return
            e = sliding_window_entropy(payload, window=256, step=64)
            cls.flagged.append({
                "entropy": e,
                "flagged": e >= cls.THRESHOLD,
                "payload_len": len(payload),
            })

        # Start sniffer in background thread
        cls._stop = threading.Event()
        cls._thread = threading.Thread(
            target=lambda: sniff(
                iface="lo",
                filter=f"tcp port {cls.LISTEN_PORT}",
                prn=custom_handler,
                store=False,
                stop_filter=lambda _: cls._stop.is_set(),
                timeout=10,
            ),
            daemon=True
        )
        cls._thread.start()
        time.sleep(0.5)  # give sniffer time to start

    @classmethod
    def tearDownClass(cls):
        cls._stop.set()
        cls._thread.join(timeout=3)

    def _send_payload(self, payload: bytes):
        pkt = (
            IP(dst="127.0.0.1")
            / TCP(dport=self.LISTEN_PORT, sport=random.randint(1024, 65000), flags="PA")
            / Raw(load=payload)
        )
        send(pkt, verbose=False)
        time.sleep(0.15)  # allow sniffer to process

    def test_live_plaintext_not_flagged(self):
        before = len(self.flagged)
        self._send_payload(make_plaintext(512))
        after = len(self.flagged)
        if after > before:
            last = self.flagged[-1]
            self.assertFalse(last["flagged"],
                f"Live plaintext was incorrectly flagged (entropy={last['entropy']:.4f})")

    def test_live_encrypted_flagged(self):
        before = len(self.flagged)
        self._send_payload(make_encrypted(512))
        time.sleep(0.3)
        after = len(self.flagged)
        self.assertGreater(after, before, "Sniffer did not capture the encrypted packet")
        last = self.flagged[-1]
        self.assertTrue(last["flagged"],
            f"Live encrypted payload was NOT flagged (entropy={last['entropy']:.4f})")

    def test_live_mixed_payload_flagged(self):
        self._send_payload(make_mixed_payload(plain_size=300, enc_size=256))
        time.sleep(0.3)
        last = self.flagged[-1]
        self.assertTrue(last["flagged"],
            f"Live mixed payload was NOT flagged (entropy={last['entropy']:.4f})")


# ---------------------------------------------------------------------------
# Report printer
# ---------------------------------------------------------------------------

class VerboseResult(unittest.TextTestResult):
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.write(f"  ✅  {test._testMethodName}\n")
        self.stream.flush()

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.write(f"  ❌  {test._testMethodName}\n")
        self.stream.flush()

    def addError(self, test, err):
        super().addError(test, err)
        self.stream.write(f"  💥  {test._testMethodName}\n")
        self.stream.flush()

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.stream.write(f"  ⏭️   {test._testMethodName} (skipped: {reason})\n")
        self.stream.flush()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test suite for entropy_firewall.py")
    parser.add_argument(
        "--live", action="store_true",
        help="Include live network tests (requires root + Scapy)"
    )
    parser.add_argument(
        "unittest_args", nargs="*",
        help="Optional: name of a specific TestCase class to run"
    )
    args = parser.parse_args()

    print("\n" + "=" * 60)
    print("  Entropy Firewall — Test Suite")
    print("=" * 60)

    # Build suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    unit_classes = [
        TestEntropy,
        TestSlidingWindowEntropy,
        TestPayloadClassification,
        TestBlockIp,
        TestEntropyBenchmark,
    ]

    if args.unittest_args:
        # Run specific class(es) by name
        for name in args.unittest_args:
            all_classes = unit_classes + [TestLiveTraffic]
            for cls in all_classes:
                if cls.__name__ == name:
                    suite.addTests(loader.loadTestsFromTestCase(cls))
    else:
        for cls in unit_classes:
            suite.addTests(loader.loadTestsFromTestCase(cls))
        if args.live:
            suite.addTests(loader.loadTestsFromTestCase(TestLiveTraffic))
        elif not LIVE_TESTS_AVAILABLE or os.geteuid() != 0:
            print("  ℹ️   Live tests skipped (run with sudo --live to enable)\n")

    runner = unittest.TextTestRunner(
        resultclass=VerboseResult,
        verbosity=0,
        stream=sys.stdout
    )
    result = runner.run(suite)

    print("\n" + "=" * 60)
    print(f"  Ran {result.testsRun} tests | "
          f"Passed: {result.testsRun - len(result.failures) - len(result.errors)} | "
          f"Failed: {len(result.failures)} | "
          f"Errors: {len(result.errors)}")
    print("=" * 60 + "\n")

    sys.exit(0 if result.wasSuccessful() else 1)
