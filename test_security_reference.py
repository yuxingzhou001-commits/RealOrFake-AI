import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from security_reference import sign_command, verify_command


KEY = b"local-fixture-only"
FIRST = {
    "sequence": 1,
    "angle": 30,
    "tag": "018565e053837453b70167a175875a2d4a9c5cf6491604c36ba8b0cd7688af33",
}
SECOND = {
    "sequence": 2,
    "angle": 45,
    "tag": "c74042acb730fdabe7832c458d696fca79978297d95feb1cbe93d5c65453175a",
}


class ServoVerificationTest(unittest.TestCase):
    def test_signer_matches_fixed_samples(self):
        with closing(sqlite3.connect(":memory:")) as state:
            for sample in (FIRST, SECOND):
                with self.subTest(sequence=sample["sequence"]):
                    payload = sign_command(sample["sequence"], sample["angle"], KEY)
                    self.assertEqual(json.loads(payload), sample)
                    self.assertEqual(verify_command(payload, KEY, state), "accepted")

    def test_signer_rejects_invalid_fields_and_empty_key(self):
        for sequence, angle, key in [(0, 30, KEY), (1, 181, KEY), (1, 30, b"")]:
            with self.subTest(sequence=sequence, angle=angle, empty_key=not key):
                with self.assertRaises(ValueError):
                    sign_command(sequence, angle, key)
        with closing(sqlite3.connect(":memory:")) as state:
            self.assertEqual(
                verify_command(json.dumps(FIRST), b"", state), "authentication_failed"
            )

    def test_valid_and_repeated_commands(self):
        with closing(sqlite3.connect(":memory:")) as state:
            self.assertEqual(verify_command(json.dumps(FIRST), KEY, state), "accepted")
            self.assertEqual(
                verify_command(json.dumps(FIRST), KEY, state), "duplicate_or_old"
            )
            self.assertEqual(verify_command(json.dumps(SECOND), KEY, state), "accepted")

    def test_rejected_command_does_not_consume_sequence(self):
        with closing(sqlite3.connect(":memory:")) as state:
            self.assertEqual(
                verify_command(json.dumps(dict(FIRST, angle=60)), KEY, state),
                "authentication_failed",
            )
            self.assertEqual(
                verify_command(json.dumps(FIRST), b"another-test-key", state),
                "authentication_failed",
            )
            self.assertEqual(verify_command(json.dumps(FIRST), KEY, state), "accepted")

    def test_state_survives_reopening_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite"
            with closing(sqlite3.connect(database)) as state:
                self.assertEqual(verify_command(json.dumps(FIRST), KEY, state), "accepted")
            with closing(sqlite3.connect(database)) as state:
                self.assertEqual(
                    verify_command(json.dumps(FIRST), KEY, state), "duplicate_or_old"
                )
                self.assertEqual(verify_command(json.dumps(SECOND), KEY, state), "accepted")

    def test_invalid_fields(self):
        with closing(sqlite3.connect(":memory:")) as state:
            for command in [dict(FIRST, angle=181), dict(FIRST, sequence=True)]:
                with self.subTest(command=command):
                    self.assertEqual(verify_command(json.dumps(command), KEY, state), "invalid")

    def test_duplicate_json_field_is_rejected(self):
        payload = '{"angle":60,' + json.dumps(FIRST)[1:]
        with closing(sqlite3.connect(":memory:")) as state:
            self.assertEqual(verify_command(payload, KEY, state), "invalid")

    def test_oversized_input_does_not_interrupt_verification(self):
        payload = "[" * 1000 + "]" * 1000
        with closing(sqlite3.connect(":memory:")) as state:
            self.assertEqual(verify_command(payload, KEY, state), "invalid")
            self.assertEqual(verify_command(json.dumps(FIRST), KEY, state), "accepted")

    def test_read_only_storage_prevents_acceptance(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "state.sqlite"
            with closing(sqlite3.connect(database)) as state:
                self.assertEqual(verify_command(json.dumps(FIRST), KEY, state), "accepted")
            with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as state:
                self.assertEqual(verify_command(json.dumps(SECOND), KEY, state), "storage_error")


if __name__ == "__main__":
    unittest.main()
