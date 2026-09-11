"""Where this server is allowed to touch the disk.

Three places, all under one root this process owns:

    ~/.technocore/identity.json   the key (read only, never written here)
    ~/.technocore/state/          our own cursors
    ~/.technocore/exports/        room exports

Nothing else. The isolation boundary in docs/DESIGN.md section 3 lists exactly
these, and a new side effect is supposed to change the tool list and that
boundary in the same diff.
"""

import os
import stat
from pathlib import Path

DEFAULT_ROOT = Path.home() / ".technocore"


def root() -> Path:
    return Path(os.environ.get("TECHNOCORE_MCP_HOME", DEFAULT_ROOT)).expanduser()


def identity_path() -> Path:
    return root() / "identity.json"


def state_dir() -> Path:
    return _ensure_private(root() / "state")


def exports_dir() -> Path:
    return _ensure_private(root() / "exports")


def _ensure_private(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)
    return path


def identity_permissions_note() -> str:
    """What the identity file's mode actually is, said plainly.

    On Windows chmod does not touch the ACL, so 'mode 600' would be a claim the
    platform does not back. Report what is true rather than what we asked for.
    """
    path = identity_path()
    if not path.exists():
        return f"no identity at {path}"
    if os.name == "nt":
        return (f"{path} exists. On Windows the mode bits do not produce an "
                "owner-only ACL; it is only as private as its directory.")
    mode = stat.S_IMODE(path.stat().st_mode)
    return f"{path} mode {mode:04o}" + ("" if mode == 0o600 else "  (expected 0600)")
