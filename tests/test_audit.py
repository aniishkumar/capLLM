"""
Unit tests for CapLLM canonical AuditLogger and cryptographic audit chain.
"""

from __future__ import annotations

import tempfile
from dataclasses import replace
from pathlib import Path
import unittest

from capllm.core.audit import AuditEvent, AuditLogger, EventType, Verdict


class TestAuditLoggerAndChain(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test_audit.jsonl"
        self.logger = AuditLogger(log_path=self.log_file)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_audit_event_creation_and_chaining(self) -> None:
        """Sequential events form an unbroken SHA-256 hash chain starting from genesis."""
        ev0 = self.logger.log_event(
            EventType.TOKEN_ISSUED, "tenant_a", "agent_1", "-", "token:1", Verdict.ALLOW, {"ttl": 60}
        )
        self.assertEqual(ev0.sequence, 0)
        self.assertEqual(ev0.previous_hash, "0" * 64)
        self.assertEqual(ev0.entry_hash, ev0.compute_hash())

        ev1 = self.logger.log_event(
            EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", "/workspace/a.txt", Verdict.ALLOW
        )
        self.assertEqual(ev1.sequence, 1)
        self.assertEqual(ev1.previous_hash, ev0.entry_hash)
        self.assertEqual(ev1.entry_hash, ev1.compute_hash())

        # Entire live chain verifies
        ok, bad_idx, msg = self.logger.verify_chain()
        self.assertTrue(ok, msg)
        self.assertIsNone(bad_idx)

    def test_modified_record_detected(self) -> None:
        """Modifying any field in an existing record is detected via content hash mismatch."""
        for i in range(5):
            self.logger.log_event(
                EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", f"file_{i}.txt", Verdict.ALLOW
            )

        events = list(self.logger.events)
        self.assertEqual(len(events), 5)

        # Attacker tampers with event #2 (flips verdict from ALLOW to BLOCK)
        tampered_entry = replace(events[2], verdict="BLOCK")
        tampered_chain = events[:2] + [tampered_entry] + events[3:]

        ok, bad_idx, msg = AuditLogger.verify_events(tampered_chain)
        self.assertFalse(ok)
        self.assertEqual(bad_idx, 2)
        self.assertIn("content hash mismatch", msg)

    def test_deleted_or_reordered_record_detected(self) -> None:
        """Deleting an interior entry breaks the hash linkage for all subsequent entries."""
        for i in range(5):
            self.logger.log_event(
                EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", f"file_{i}.txt", Verdict.ALLOW
            )

        events = list(self.logger.events)
        # Delete entry #2
        deleted_chain = events[:2] + events[3:]

        ok, bad_idx, msg = AuditLogger.verify_events(deleted_chain)
        self.assertFalse(ok)
        self.assertEqual(bad_idx, 2)
        self.assertIn("previous_hash mismatch", msg)

    def test_tail_truncation_requires_external_checkpoint(self) -> None:
        """Demonstrates why tail truncation CANNOT be detected without an external checkpoint.

        Threat explanation:
        If an attacker truncates the newest N records, the remaining prefix still
        forms a mathematically valid hash chain from genesis to the truncated head.
        Only when verified against an expected external head hash checkpoint can
        the truncation be recognized.
        """
        for i in range(6):
            self.logger.log_event(
                EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", f"file_{i}.txt", Verdict.ALLOW
            )

        full_events = list(self.logger.events)
        self.assertEqual(len(full_events), 6)
        true_head_hash = self.logger.head_hash

        # Attacker truncates the last 2 events (indices 4 and 5)
        truncated_events = full_events[:4]
        self.assertEqual(len(truncated_events), 4)

        # Without an external checkpoint: verify_events reports valid! (The vulnerability)
        ok_no_checkpoint, bad_idx, msg = AuditLogger.verify_events(truncated_events)
        self.assertTrue(ok_no_checkpoint)
        self.assertIsNone(bad_idx)
        self.assertEqual(msg, "chain intact")

        # WITH an external checkpoint: tail truncation is immediately caught!
        ok_with_checkpoint, bad_idx_cp, msg_cp = AuditLogger.verify_events(
            truncated_events, expected_head_hash=true_head_hash
        )
        self.assertFalse(ok_with_checkpoint)
        self.assertEqual(bad_idx_cp, 4)
        self.assertIn("checkpoint mismatch", msg_cp)
        self.assertIn("tail truncated", msg_cp)

    def test_ondisk_jsonl_logging_and_verification(self) -> None:
        """Events appended to JSONL file on disk can be loaded and verified."""
        for i in range(4):
            self.logger.log_event(
                EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", f"file_{i}.txt", Verdict.ALLOW
            )

        # File exists and contains valid JSON lines
        self.assertTrue(self.log_file.exists())
        lines = [line.strip() for line in self.log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 4)

        # Verify from disk
        ok, bad_idx, msg = AuditLogger.verify_file(self.log_file, expected_head_hash=self.logger.head_hash)
        self.assertTrue(ok, msg)
        self.assertIsNone(bad_idx)

    def test_fresh_run_ledger_truncation(self) -> None:
        """Constructing a new AuditLogger resets/truncates the ledger for a fresh run."""
        # Session 1: log 3 events
        for i in range(3):
            self.logger.log_event(
                EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", f"session1_{i}.txt", Verdict.ALLOW
            )
        self.assertEqual(len(self.logger), 3)
        self.assertEqual(len(self.log_file.read_text(encoding="utf-8").strip().splitlines()), 3)

        # Session 2: New AuditLogger instance pointing to the same file starts a fresh ledger
        session2_logger = AuditLogger(log_path=self.log_file)
        # Previous file content must be truncated to start a fresh chain from genesis
        self.assertEqual(len(session2_logger), 0)
        self.assertEqual(session2_logger.head_hash, "0" * 64)
        self.assertEqual(self.log_file.read_text(encoding="utf-8"), "")

        # Logging an event in session 2 starts at sequence 0 with genesis previous_hash
        ev = session2_logger.log_event(
            EventType.ACCESS_ALLOWED, "tenant_a", "agent_2", "openat", "session2_0.txt", Verdict.ALLOW
        )
        self.assertEqual(ev.sequence, 0)
        self.assertEqual(ev.previous_hash, "0" * 64)
        ok, _, msg = session2_logger.verify_chain()
        self.assertTrue(ok, msg)

    def test_flush_behavior(self) -> None:
        """Log events are immediately flushed to the operating system on write."""
        self.logger.log_event(
            EventType.ACCESS_ALLOWED, "tenant_a", "agent_1", "openat", "flushed_file.txt", Verdict.ALLOW
        )
        # Read from file without closing logger; entry must be immediately readable
        lines = self.log_file.read_text(encoding="utf-8").strip().splitlines()
        self.assertEqual(len(lines), 1)
        self.assertIn("flushed_file.txt", lines[0])


if __name__ == "__main__":
    unittest.main()
