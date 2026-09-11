"""Entry point.

    python -m technocore_mcp             serve MCP over stdio (the default)
    python -m technocore_mcp check-note  compare the published DID note with ours
    python -m technocore_mcp doctor      startup checks only, then exit

`check-note` exists because the DID note cannot be defended, only watched: the
note is world-writable, so anyone can overwrite it whether or not this agent is
involved. It reports a mismatch and does not repair it -- a silent repair is a
repair nobody notices, and noticing is the whole point.
"""

import sys

from . import server, vendor_facade
from .routes import ROUTE_KV_READ, fetch_technocore
from .tools import _identity


def check_note() -> int:
    vendor = server.startup_checks()
    identity = _identity(vendor)
    expected = vendor.note_value(identity)
    fp = vendor.fingerprint(identity["did"])

    for namespace, key in ((f"did-{fp[:2]}", fp[2:]), ("did", fp)):
        got = fetch_technocore(ROUTE_KV_READ, {"ns": namespace, "key": key})
        where = f"/kv/{namespace}/{key}"
        if got.status != 200 or not got.body.strip():
            print(f"absent   {where}")
            continue
        if got.body.strip() == expected.strip():
            print(f"ok       {where}")
            return 0
        print(f"MISMATCH {where}")
        print("  the published note is not this identity's value.")
        print("  Not repairing it: decide deliberately, then republish by hand.")
        return 2

    print("MISSING  no note published for this DID at either coordinate.")
    print("  If that is unexpected, someone cleared it. Republish by hand.")
    return 2


def doctor() -> int:
    from . import paths
    from .routes import configured_host
    from .vendorguard import ALLOWED, actual_sha256
    vendor = server.startup_checks()
    print(f"vendored client sha256 : {actual_sha256()}  (matches UPSTREAM.txt)")
    print(f"vendor BASE            : {vendor.BASE}")
    print(f"configured host        : {configured_host()}")
    print(f"allowlisted symbols    : {len(ALLOWED)}")
    print(f"identity               : {paths.identity_permissions_note()}")
    print(f"exports directory      : {paths.exports_dir()}")
    print("startup checks passed")
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if not argv:
        return server.serve()
    command = argv[0]
    if command == "check-note":
        return check_note()
    if command == "doctor":
        return doctor()
    if command == "serve":
        return server.serve()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
