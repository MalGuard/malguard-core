"""Subprocess tests using inert publishers; no network, keys or samples."""

from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WRAPPER = ROOT / "tools/ci/publish_cleanroom_feed.py"


class PublisherDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.wrapper = self.root / "tools/ci/publish_cleanroom_feed.py"
        self.wrapper.parent.mkdir(parents=True)
        shutil.copyfile(WRAPPER, self.wrapper)
        self.publisher = self.root / "cleanroom-source/packaging/online/publish_feed.py"
        self.publisher.parent.mkdir(parents=True)
        self.output = self.root / "prior-feed.json"
        self.output.write_bytes(b"previous authenticated feed fixture")
        self.original_hash = hashlib.sha256(self.output.read_bytes()).digest()

    def run_publisher(self, source):
        self.publisher.write_text(source, encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(self.wrapper), "--output", str(self.output), "--epoch", "42"],
            cwd=self.root,
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def test_http_failures_stop_and_do_not_expose_upstream_details(self):
        cases = {
            401: "access denied",
            403: "access denied",
            429: "rate-limited",
            500: "5xx",
            503: "5xx",
            302: "HTTP error",
            404: "HTTP error",
        }
        for code, expected in cases.items():
            with self.subTest(code=code):
                result = self.run_publisher(
                    "from urllib.error import HTTPError\n"
                    "from io import BytesIO\n"
                    f"raise HTTPError('https://invalid.test/leaked-url', {code}, "
                    "'leaked-reason\\n::warning::injected', "
                    "{'Auth-Key': 'fixture-secret'}, BytesIO(b'leaked-body'))\n"
                )
                self.assertEqual(result.returncode, 1)
                self.assertIn(expected, result.stderr)
                self.assertIn("downstream publication must remain blocked", result.stderr)
                self.assertEqual(result.stdout, "")
                for forbidden in (
                    "leaked-url", "leaked-reason", "fixture-secret", "leaked-body",
                    "::warning::", "Traceback",
                ):
                    self.assertNotIn(forbidden, result.stderr)
                self.assertEqual(
                    hashlib.sha256(self.output.read_bytes()).digest(), self.original_hash
                )

    def test_success_forwards_arguments_and_preserves_publisher_output(self):
        result = self.run_publisher(
            "import argparse\nfrom pathlib import Path\n"
            "p = argparse.ArgumentParser()\n"
            "p.add_argument('--output', type=Path, required=True)\n"
            "p.add_argument('--epoch', type=int, required=True)\n"
            "args = p.parse_args()\n"
            "assert args.epoch == 42\n"
            "args.output.write_bytes(b'new harmless feed fixture')\n"
            "print('fixture publisher completed')\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "fixture publisher completed\n")
        self.assertEqual(result.stderr, "")
        self.assertEqual(self.output.read_bytes(), b"new harmless feed fixture")

    def test_publisher_exit_failure_is_not_converted_to_success(self):
        result = self.run_publisher("raise SystemExit(7)\n")
        self.assertEqual(result.returncode, 7)
        self.assertNotIn("publication", result.stdout)
        self.assertEqual(self.output.read_bytes(), b"previous authenticated feed fixture")

    def test_non_http_security_failure_propagates(self):
        result = self.run_publisher("raise ValueError('Signing key does not match')\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Signing key does not match", result.stderr)
        self.assertNotIn("access denied", result.stderr)
        self.assertEqual(self.output.read_bytes(), b"previous authenticated feed fixture")

    def test_missing_publisher_fails(self):
        result = subprocess.run(
            [sys.executable, str(self.wrapper)],
            cwd=self.root, text=True, capture_output=True, timeout=15, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.output.read_bytes(), b"previous authenticated feed fixture")


if __name__ == "__main__":
    unittest.main()
