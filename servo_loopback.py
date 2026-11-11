"""Run the signing and verification reference over local HTTP."""

import argparse
import os
import sqlite3
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from security_reference import MAX_PAYLOAD_LENGTH, sign_command, verify_command


HOST = "127.0.0.1"


def initialize(database):
    path = Path(database)
    with path.open("xb"):
        pass
    with closing(sqlite3.connect(path)) as state, state:
        state.execute(
            "CREATE TABLE replay_state (slot INTEGER PRIMARY KEY, sequence INTEGER NOT NULL)"
        )
        state.execute("INSERT INTO replay_state VALUES (1, 0)")


def serve(port, database, key):
    uri = Path(database).resolve().as_uri() + "?mode=rw"
    with closing(sqlite3.connect(uri, uri=True)) as state:
        record = state.execute(
            "SELECT sequence FROM replay_state WHERE slot = 1"
        ).fetchone()
        if record is None or type(record[0]) is not int or not 0 <= record[0] <= 2**31 - 1:
            raise ValueError("missing or invalid sequence record")

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path != "/command":
                    self.send_error(404)
                    return
                lengths = self.headers.get_all("Content-Length", [])
                length = lengths[0] if len(lengths) == 1 else ""
                if self.headers.get("Transfer-Encoding") or not (
                    length.isascii() and length.isdecimal() and len(length) <= 3
                    and 0 < int(length) <= MAX_PAYLOAD_LENGTH
                ):
                    self.send_error(400)
                    return
                self.connection.settimeout(3)
                try:
                    raw = self.rfile.read(int(length))
                    verdict = (
                        verify_command(raw.decode("ascii"), key, state)
                        if len(raw) == int(length) else "invalid"
                    )
                except (TimeoutError, UnicodeDecodeError):
                    verdict = "invalid"

                if verdict == "accepted":
                    print("SIMULATED SERVO ACTION", flush=True)
                status = {"accepted": 200, "authentication_failed": 403,
                          "duplicate_or_old": 409, "storage_error": 503}.get(verdict, 400)
                body = (verdict + "\n").encode("ascii")
                self.send_response(status)
                self.send_header("Content-Type", "text/plain; charset=ascii")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        with HTTPServer((HOST, port), Handler) as server:
            print(f"Listening on http://{HOST}:{server.server_port}", flush=True)
            server.serve_forever()


def send(port, sequence, angle, key):
    payload = sign_command(sequence, angle, key).encode("ascii")
    request = Request(f"http://{HOST}:{port}/command", data=payload,
                      headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=5) as response:
            print(response.read().decode("ascii").strip())
        return 0
    except HTTPError as error:
        with error:
            print(error.read().decode("ascii").strip())
        return 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8765)
    modes = parser.add_subparsers(dest="mode", required=True)
    init = modes.add_parser("init")
    init.add_argument("--state", required=True)
    board = modes.add_parser("board")
    board.add_argument("--state", required=True)
    client = modes.add_parser("send")
    client.add_argument("sequence", type=int)
    client.add_argument("angle", type=int)
    args = parser.parse_args()
    if args.mode == "init":
        try:
            initialize(args.state)
        except (OSError, sqlite3.Error) as error:
            parser.error(f"initialization failed: {error}")
        print("Initialized new sequence state")
        return 0
    key = os.environ.get("SERVO_DEMO_KEY")
    if not key:
        parser.error("set SERVO_DEMO_KEY in both terminals")
    if args.mode == "board":
        try:
            serve(args.port, args.state, key.encode("utf-8"))
        except KeyboardInterrupt:
            return 0
        except (OSError, sqlite3.Error, ValueError) as error:
            parser.error(f"board unavailable: {error}")
    else:
        try:
            return send(args.port, args.sequence, args.angle, key.encode("utf-8"))
        except (OSError, ValueError) as error:
            parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
