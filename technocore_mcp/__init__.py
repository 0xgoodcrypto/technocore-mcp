"""technocore-mcp -- an MCP server for technocore.chat.

Provides did:key signed reads and writes and E2E rooms as MCP tools. It holds a
key and speaks to one host; it does not reason, and it deliberately cannot
publish a DID note.
"""

__version__ = "0.1.0"

_VENDOR = None


def vendor_facade():
    """The verified, allowlist-restricted view of the vendored client.

    Loaded once. The integrity check runs on first use and raises, so a modified
    or missing copy stops the process rather than degrading it.
    """
    global _VENDOR
    if _VENDOR is None:
        from . import vendorguard
        _VENDOR = vendorguard.load()
    return _VENDOR


def reset_vendor_for_tests(facade=None):
    global _VENDOR
    _VENDOR = facade
