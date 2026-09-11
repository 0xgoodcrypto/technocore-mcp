"""Writing a room export to disk.

The bytes being written are attacker-chosen: a room export is whatever strangers
put in the room. So the destination is not negotiable and no argument moves it.

An earlier revision took an `out_path` argument. It was removed because a tool
argument is the calling model's output, and untrusted room content is that
model's input -- so `out_path` was equivalent to letting the attacker pick where
their bytes land.
"""

import os
import re
from datetime import datetime, timezone
from pathlib import Path

from . import paths

MAX_EXPORT_BYTES = 64 * 1024 * 1024
_SAFE_GENERATION = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


class ExportError(RuntimeError):
    pass


def _write_at(target: Path, raw: bytes) -> None:
    """Create and write, or fail. Never truncate, never follow a link.

    O_EXCL so an existing file is an error rather than a silent replacement, and
    O_NOFOLLOW (POSIX) so a symlink dropped in place of the name we generated
    cannot redirect the write.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(target, flags, 0o600)
    except FileExistsError:
        raise ExportError(f"{target} already exists; not overwriting") from None
    except OSError as exc:
        raise ExportError(f"could not create {target}: {exc}") from None
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)


def _generation_tag(generation) -> str:
    """X-Room-Generation comes off the wire, so it is not a filename yet."""
    if generation is None:
        return "nogen"
    text = str(generation).strip()
    return text if _SAFE_GENERATION.match(text) else "gen-unparsed"


def write_export(room: str, body: str, generation=None) -> dict:
    """Write one export. Server-owned directory, server-generated name.

    `room` has already passed NAME_RE by the time it gets here -- it reached us
    as a validated route segment -- so it cannot introduce a separator. The
    containment check below is not relying on that: it re-checks the resolved
    result, the same way the origin check re-checks an assembled URL.
    """
    raw = body.encode("utf-8")
    if len(raw) > MAX_EXPORT_BYTES:
        raise ExportError(
            f"export is {len(raw)} bytes, over the {MAX_EXPORT_BYTES} byte cap")

    base = paths.exports_dir().resolve()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    target = (base / f"{room}-{_generation_tag(generation)}-{stamp}.jsonl").resolve()

    if not target.is_relative_to(base):
        raise ExportError(f"refusing to write outside {base}: {target}")
    if target.parent != base:
        raise ExportError(f"refusing a nested destination: {target}")

    _write_at(target, raw)

    return {
        "path": str(target),
        "bytes": len(raw),
        "records": body.count("\n") + (0 if body.endswith("\n") or not body else 1),
        "generation": None if generation is None else str(generation),
    }
