"""Process-level checks for the local simulated board."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import contextmanager
from pathlib import Path


SCRIPT = Path(__file__).with_name("servo_loopback.py")
PYTHON = [sys.executable, "-B", str(SCRIPT)]
ENV = dict(os.environ, SERVO_DEMO_KEY="local-fixture-only")
LISTENING = "Listening on http://127.0.0.1:"
ACTION = "SIMULATED SERVO ACTION"


def run(*args):
    return subprocess.run(
        [*PYTHON, *args], env=ENV, capture_output=True, text=True, timeout=8
    )


@contextmanager
def board(state, log):
    with log.open("w", encoding="utf-8") as output:
        process = subprocess.Popen(
            [*PYTHON, "--port", "0", "board", "--state", str(state)],
            env=ENV, stdout=output, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and process.poll() is None:
                for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                    if line.startswith(LISTENING):
                        yield line.removeprefix(LISTENING)
                        return
                time.sleep(0.05)
            raise RuntimeError(f"Simulated board did not start: {log.read_bytes()!r}")
        finally:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=5)


class SimulatedBoardTest(unittest.TestCase):
    def test_missing_state_prevents_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.sqlite"
            result = run("--port", "0", "board", "--state", str(state))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("board unavailable", result.stderr)
            self.assertNotIn(LISTENING, result.stdout)
            self.assertFalse(state.exists())

    def test_initialized_state_survives_process_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory) / "state.sqlite"
            log = Path(directory) / "board.log"
            result = run("init", "--state", str(state))
            self.assertEqual(result.returncode, 0, result.stderr)
            with board(state, log) as port:
                self.assert_verdict(port, "1", "30", 0, "accepted")
            self.assertEqual(log.read_bytes().count(ACTION.encode()), 1)

            with board(state, log) as port:
                self.assert_verdict(port, "1", "30", 1, "duplicate_or_old")
                self.assertEqual(log.read_bytes().count(ACTION.encode()), 0)
                self.assert_verdict(port, "2", "45", 0, "accepted")
            self.assertEqual(log.read_bytes().count(ACTION.encode()), 1)

    def assert_verdict(self, port, sequence, angle, code, verdict):
        result = run("--port", port, "send", sequence, angle)
        self.assertEqual(result.returncode, code, result.stderr)
        self.assertEqual(result.stdout.strip(), verdict)
