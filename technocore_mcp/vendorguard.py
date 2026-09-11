"""Load the vendored e2e.py, verify its bytes, and expose only what MCP may call.

Two jobs, deliberately kept apart:

1. **Integrity** -- the copy is the bytes we recorded. Fail closed if not.
2. **Reach** -- MCP code can touch only the names on the allowlist.

(2) is enforced here at runtime *and* again as a static test, because "we do not
call that" is a claim that decays with time, and a test that fails is not.

The allowlist is closed by default. A name that is not listed is unreachable,
including names that do not exist yet -- a new upstream CLI command cannot
become reachable by being added upstream.
"""

import hashlib
import importlib.util
import re
from pathlib import Path

_PACKAGE_DIR = Path(__file__).resolve().parent


def _locate_vendor_dir() -> Path:
    """Where the vendored copy lives, in both layouts it can be in.

    Installed, `vendor/` arrives inside the package (pyproject maps it to
    `technocore_mcp.vendor`). In a source checkout it sits beside the package at
    the repository root. Look for the installed location first and fall back, so
    the same code works from a wheel and from a clone.

    An earlier revision only ever looked beside the package, while pyproject said
    `vendor/` shipped and shipped nothing -- so an installed wheel failed its own
    integrity check on startup. The comment asserted a property the packaging did
    not have.
    """
    inside = _PACKAGE_DIR / "vendor"
    if (inside / "e2e.py").exists():
        return inside
    return _PACKAGE_DIR.parent / "vendor"


VENDOR_DIR = _locate_vendor_dir()
VENDOR_FILE = VENDOR_DIR / "e2e.py"
UPSTREAM_FILE = VENDOR_DIR / "UPSTREAM.txt"

# name -> what calling it does. An entry cannot be added with this column empty:
# the risk of a row is set by neither the function name nor the argument name,
# but by who holds the bytes that decide the destination or the side effect.
ALLOWED = {
    "validate_name": "none -- raises unless the name matches NAME_RE",
    "sweep_single_line": "none -- pure string normalisation",
    "random_room": "none -- os.urandom rendered as a name",
    "fingerprint": "none -- sha256 over the did string",
    "note_value": "none -- string composition",
    "seal_room_key": "none -- pure crypto",
    "open_room_key": "none -- pure crypto",
    "encrypt_line": "none -- pure crypto",
    "decrypt_line": "none -- pure crypto",
    "sealing_key": "none -- key object from an already-loaded identity dict",
    "load_identity": "file read -- the identity file only; never writes",
    "say_signed": (
        "network -- builds f\"{BASE}/r/{validate_name(room)}/say-signed/...\" "
        "internally. BASE is followed by a literal '/' and the variable part has "
        "passed NAME_RE, so caller bytes cannot reach the authority. "
        "See vendor/REVIEW_POINTS.md before accepting an upstream change here."
    ),
    "BASE": "none -- constant; read only to check it agrees with our host",
    "MESSAGE_CAP": "none -- constant",
}

# Named here so the test asserts on them by name rather than only by absence.
# Absence is what actually enforces the rule; this list documents the ones whose
# reachability would be a specific, known regression.
DENIED_BY_NAME = (
    "get",  # takes a full URL. An unbounded fetch primitive.
    "post",  # BASE + path, and no caller outside say_signed. Unneeded surface.
    "note_urls",  # builds the /kv/ coordinates that the write route extends.
    "main",
    "create_identity",
    "save_identity",
    "resolve_identity_path",
    "enclosing_git_worktree",
)


class VendorIntegrityError(RuntimeError):
    """The vendored copy is not the bytes we recorded."""


class VendorAccessError(AttributeError):
    """MCP code reached for a vendor name that is not on the allowlist."""


class Vendor:
    """Attribute access restricted to ALLOWED.

    The vendored module's own internals are untouched: `say_signed` still
    resolves `get` through its own module globals. This facade constrains what
    *our* code can reach, which is the thing we can actually promise.
    """

    def __init__(self, module):
        object.__setattr__(self, "_module", module)

    def __getattr__(self, name):
        if name not in ALLOWED:
            raise VendorAccessError(
                f"vendor.{name} is not on the allowlist. "
                f"If MCP code needs it, add it to ALLOWED in vendorguard.py "
                f"with its side effect stated -- and if you cannot state the "
                f"side effect in one line, do not add it."
            )
        return getattr(object.__getattribute__(self, "_module"), name)

    def __setattr__(self, name, value):
        raise VendorAccessError("the vendored module is read-only from here")

    def __dir__(self):
        return sorted(ALLOWED)


def recorded_sha256(upstream_file: Path = UPSTREAM_FILE) -> str:
    text = upstream_file.read_text(encoding="utf-8")
    found = re.search(r"^sha256:\s*([0-9a-f]{64})\s*$", text, re.M)
    if not found:
        raise VendorIntegrityError(f"no sha256 line in {upstream_file}")
    return found.group(1)


def actual_sha256(vendor_file: Path = VENDOR_FILE) -> str:
    return hashlib.sha256(vendor_file.read_bytes()).hexdigest()


def verify(vendor_file: Path = VENDOR_FILE, upstream_file: Path = UPSTREAM_FILE) -> str:
    """Raise unless the copy matches what UPSTREAM.txt records. Returns the digest.

    This detects local modification and corruption. It does NOT detect upstream
    having moved on, and it does not detect a digest replaced along with the
    copy -- both sides of this comparison live in vendor/. Freshness is a
    separate check; see UPSTREAM.txt.
    """
    if not vendor_file.exists():
        raise VendorIntegrityError(f"vendored client missing: {vendor_file}")
    expected = recorded_sha256(upstream_file)
    got = actual_sha256(vendor_file)
    if got != expected:
        raise VendorIntegrityError(
            f"{vendor_file} does not match the digest recorded in {upstream_file}.\n"
            f"  recorded: {expected}\n"
            f"  actual:   {got}\n"
            "Refusing to start. Restore the recorded copy, or update UPSTREAM.txt "
            "deliberately after reading vendor/REVIEW_POINTS.md."
        )
    return got


def load(vendor_file: Path = VENDOR_FILE, upstream_file: Path = UPSTREAM_FILE) -> Vendor:
    """Verify, import, and wrap. Startup calls this and dies on failure."""
    verify(vendor_file, upstream_file)
    spec = importlib.util.spec_from_file_location(
        "technocore_mcp._vendored_e2e", vendor_file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    missing = sorted(n for n in ALLOWED if not hasattr(module, n))
    if missing:
        raise VendorIntegrityError(
            f"the allowlist names symbols the vendored client does not have: "
            f"{missing}. An allowlist that names something absent checks nothing."
        )
    return Vendor(module)
