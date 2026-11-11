"""Reference command signing and verification for the servo prototype."""

import hashlib
import hmac
import json
import sqlite3
from string import hexdigits

MAX_PAYLOAD_LENGTH = 512


def signed_bytes(sequence: int, angle: int) -> bytes:
    """Encode the two authenticated fields in a fixed order."""
    return f"servo-v1:{sequence}:{angle}".encode("ascii")


def _valid_command_fields(sequence: object, angle: object) -> bool:
    return (
        type(sequence) is int and 1 <= sequence <= 2**31 - 1
        and type(angle) is int and 0 <= angle <= 180
    )


def _command_tag(sequence: int, angle: int, key: bytes) -> str:
    return hmac.new(key, signed_bytes(sequence, angle), hashlib.sha256).hexdigest()


def sign_command(sequence: int, angle: int, key: bytes) -> str:
    """Create the JSON payload for a new authorized command."""
    if not _valid_command_fields(sequence, angle):
        raise ValueError("invalid sequence or angle")
    if not key:
        raise ValueError("a signing key is required")
    return json.dumps(
        {"sequence": sequence, "angle": angle, "tag": _command_tag(sequence, angle, key)},
        separators=(",", ":"),
    )


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    fields = {}
    for name, value in pairs:
        if name in fields:
            raise ValueError("duplicate JSON field")
        fields[name] = value
    return fields


def verify_command(payload: str, key: bytes, state: sqlite3.Connection) -> str:
    """Return a verdict, recording an accepted sequence before any actuation."""
    if len(payload) > MAX_PAYLOAD_LENGTH or not payload.isascii():
        return "invalid"
    try:
        command = json.loads(payload, object_pairs_hook=_unique_fields)
    except ValueError:
        return "invalid"
    if not isinstance(command, dict) or set(command) != {"sequence", "angle", "tag"}:
        return "invalid"
    sequence, angle, tag = command["sequence"], command["angle"], command["tag"]
    if (
        not _valid_command_fields(sequence, angle)
        or not isinstance(tag, str) or len(tag) != 64
        or any(character not in hexdigits[:16] for character in tag)
    ):
        return "invalid"

    if not key:
        return "authentication_failed"
    expected = _command_tag(sequence, angle, key)
    if not hmac.compare_digest(tag, expected):
        return "authentication_failed"

    try:
        with state:
            state.execute(
                "CREATE TABLE IF NOT EXISTS replay_state "
                "(slot INTEGER PRIMARY KEY, sequence INTEGER NOT NULL)"
            )
            result = state.execute(
                "INSERT INTO replay_state VALUES (1, ?) "
                "ON CONFLICT(slot) DO UPDATE SET sequence = excluded.sequence "
                "WHERE excluded.sequence > replay_state.sequence",
                (sequence,),
            )
    except sqlite3.Error:
        return "storage_error"
    return "accepted" if result.rowcount else "duplicate_or_old"
