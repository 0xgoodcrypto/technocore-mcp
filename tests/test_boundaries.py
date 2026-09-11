"""The checks that hold the design's boundaries in place.

Each test here corresponds to something that was got wrong at least once while
the design was being reviewed, which is the reason it is a test and not a note.
"""

import ast
import json
import unittest
import urllib.parse
from pathlib import Path

from technocore_mcp import routes, tools, vendor_facade, vendorguard
from technocore_mcp.routes import OriginError, RouteError

PACKAGE = Path(__file__).resolve().parent.parent / "technocore_mcp"

# Import machinery that can produce a module without going through vendorguard.
# It is allowed in exactly one file, which is the one that checks the digest
# first. Anywhere else it is a way around the check.
DYNAMIC_IMPORT_CALLS = {
    "import_module", "__import__", "spec_from_file_location",
    "module_from_spec", "exec_module", "load_module", "SourceFileLoader",
}

# ...but matching call *names* cannot see through an alias: rename it at the
# import (`from importlib import import_module as im`) and the call site no
# longer says any banned word. So the real rule is applied one step earlier --
# these modules may not be imported at all outside vendorguard, under any name.
# An alias cannot hide an import statement, because the import statement is
# where the alias is created.
FORBIDDEN_IMPORT_ROOTS = {"importlib", "runpy", "pkgutil", "imp", "zipimport"}


def _names_the_vendor(dotted: str) -> bool:
    """True if a dotted module path reaches the vendored client.

    Compares whole segments, so `vendorguard` -- which is the legitimate way in
    -- is not caught by a prefix match on `vendor`.
    """
    parts = dotted.split(".")
    return "vendor" in parts or "e2e" in parts


def forbidden_vendor_imports(source: str, filename: str = "<source>") -> list:
    """Every way this source reaches the vendored client other than vendorguard.

    Packaging the vendored copy as `technocore_mcp.vendor` (so it ships in the
    wheel) made it importable by name. Loading it that way would skip the digest
    check entirely -- the integrity guarantee is only worth what the *only* path
    to the module is worth.
    """
    problems = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _names_the_vendor(alias.name):
                    problems.append(f"import {alias.name}")
                # The alias is irrelevant: the module is banned, not the name
                # it is bound to.
                if alias.name.split(".")[0] in FORBIDDEN_IMPORT_ROOTS:
                    as_part = f" as {alias.asname}" if alias.asname else ""
                    problems.append(f"import {alias.name}{as_part}")
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            dots = "." * node.level
            if _names_the_vendor(module):
                problems.append(f"from {dots}{module} import ...")
            if not node.level and module.split(".")[0] in FORBIDDEN_IMPORT_ROOTS:
                names = ", ".join(
                    a.name + (f" as {a.asname}" if a.asname else "") for a in node.names)
                problems.append(f"from {module} import {names}")
            for alias in node.names:
                if alias.name in ("vendor", "e2e"):
                    problems.append(f"from {dots}{module} import {alias.name}")
        elif isinstance(node, ast.Call):
            func = node.func
            called = None
            if isinstance(func, ast.Attribute):
                called = func.attr
            elif isinstance(func, ast.Name):
                called = func.id
            if called in DYNAMIC_IMPORT_CALLS:
                problems.append(f"dynamic import via {called}()")
            # getattr(m, "import_module") reaches a helper without ever naming
            # it as an attribute or an import.
            if called == "getattr":
                for argument in node.args[1:]:
                    if (isinstance(argument, ast.Constant)
                            and argument.value in DYNAMIC_IMPORT_CALLS):
                        problems.append(f"getattr(..., {argument.value!r})")
        elif isinstance(node, ast.Name) and node.id == "__import__":
            # Catches `f = __import__` as well as `__import__(...)`, since a
            # bound reference is called later under a different name.
            problems.append("reference to __import__")
    return problems

# Arguments that would each be a model-supplied value standing in for something a
# model cannot supply: a human's approval, an out-of-band check, a safe
# destination, or a decision to hand back an executable URL.
FORBIDDEN_ARGUMENTS = {
    "confirm", "confirmed", "approve", "approved",
    "out_path", "output_path", "path", "destination", "dest", "filename",
    "corroborated", "key_is_corroborated", "verified", "trusted",
    "include_write_url", "write_url", "url", "publish",
}


class VendorAllowlist(unittest.TestCase):
    def test_every_allowlisted_name_exists_in_the_vendored_client(self):
        """An allowlist that names something absent checks nothing.

        A previous revision listed `open_sealed` -- the MCP tool name, not the
        vendored symbol (`open_room_key`). The test written from it would have
        passed while proving nothing.
        """
        module = vendorguard.load()._module
        for name in vendorguard.ALLOWED:
            self.assertTrue(hasattr(module, name),
                            f"allowlist names {name!r}, which the vendor lacks")

    def test_every_allowlist_entry_states_its_side_effect(self):
        for name, effect in vendorguard.ALLOWED.items():
            self.assertTrue(effect.strip(), f"{name} has no side effect stated")

    def test_denied_names_are_not_on_the_allowlist(self):
        for name in vendorguard.DENIED_BY_NAME:
            self.assertNotIn(name, vendorguard.ALLOWED)

    def test_the_facade_refuses_a_name_that_is_not_allowlisted(self):
        vendor = vendor_facade()
        for name in ("get", "post", "note_urls", "cmd_note", "cmd_seal", "main",
                     "save_identity", "create_identity"):
            with self.assertRaises(vendorguard.VendorAccessError, msg=name):
                getattr(vendor, name)

    def test_integrity_check_fails_on_a_modified_copy(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / "e2e.py"
            copy.write_bytes(vendorguard.VENDOR_FILE.read_bytes() + b"\n# tampered\n")
            with self.assertRaises(vendorguard.VendorIntegrityError):
                vendorguard.verify(copy, vendorguard.UPSTREAM_FILE)


class ImportGraph(unittest.TestCase):
    """No MCP module may reach a vendor name off the allowlist."""

    def _vendor_attribute_names(self):
        found = {}
        for source in PACKAGE.glob("*.py"):
            tree = ast.parse(source.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Attribute):
                    continue
                target = node.value
                reached = (
                    (isinstance(target, ast.Name) and target.id == "vendor")
                    or (isinstance(target, ast.Call)
                        and isinstance(target.func, ast.Name)
                        and target.func.id == "vendor_facade")
                )
                if reached:
                    found.setdefault(node.attr, set()).add(source.name)
        return found

    def test_no_module_reaches_outside_the_allowlist(self):
        for name, where in self._vendor_attribute_names().items():
            self.assertIn(name, vendorguard.ALLOWED,
                          f"{sorted(where)} reaches vendor.{name}, not allowlisted")

    def test_the_allowlist_has_no_unused_entries(self):
        """Nothing stays on the allowlist because it is 'probably fine'.

        `post` was kept one round on that reasoning, on the strength of its
        argument being *named* `path`.
        """
        used = set(self._vendor_attribute_names())
        unused = sorted(set(vendorguard.ALLOWED) - used)
        self.assertEqual(unused, [], f"allowlisted but never called: {unused}")

    def _mcp_sources(self):
        """Every module of this package except the one allowed to load the vendor.

        Skips anything under a `vendor/` directory: in an installed layout the
        vendored copy sits inside the package, and it is not our code.
        """
        for source in PACKAGE.rglob("*.py"):
            if source.name == "vendorguard.py":
                continue
            if "vendor" in source.relative_to(PACKAGE).parts:
                continue
            yield source

    def test_no_module_reaches_the_vendored_client_except_through_vendorguard(self):
        """The digest check is worth what the only path to the module is worth.

        Shipping the vendored copy inside the package made it importable as
        `technocore_mcp.vendor.e2e`. Reaching it that way -- by name, by relative
        import, or through importlib -- would produce the module without
        verifying a single byte.
        """
        for source in self._mcp_sources():
            problems = forbidden_vendor_imports(
                source.read_text(encoding="utf-8"), source.name)
            self.assertEqual(problems, [],
                             f"{source.name} reaches the vendored client: {problems}")

    def test_the_detector_catches_the_bypasses_it_claims_to(self):
        """A detector nobody tried to evade is a detector nobody has tested.

        Each of these is a real way to load the vendored client without the
        digest check, and each must be flagged.
        """
        bypasses = [
            "from technocore_mcp.vendor import e2e",
            "from technocore_mcp import vendor",
            "import technocore_mcp.vendor.e2e",
            "import technocore_mcp.vendor.e2e as client",
            "from .vendor import e2e",
            "from . import vendor",
            "from vendor import e2e",
            "import vendor.e2e",
            "import e2e",
            "import importlib\nm = importlib.import_module('technocore_mcp.vendor.e2e')",
            "m = __import__('technocore_mcp.vendor.e2e')",
            "import importlib.util\n"
            "s = importlib.util.spec_from_file_location('x', 'vendor/e2e.py')",
            "from importlib.machinery import SourceFileLoader\n"
            "m = SourceFileLoader('x', 'vendor/e2e.py').load_module()",
            # Aliased: nothing at the call site says any banned word, which is
            # why the rule has to bite at the import statement instead.
            "from importlib import import_module as im\n"
            "m = im('technocore_mcp.vendor.e2e')",
            "from importlib.util import spec_from_file_location as sffl\n"
            "s = sffl('x', 'vendor/e2e.py')",
            "import importlib as il\nm = il.import_module('technocore_mcp.vendor.e2e')",
            # Reached without importing the helper by name at all.
            "import importlib\ng = getattr(importlib, 'import_module')\nm = g('x')",
            "f = __import__\nm = f('technocore_mcp.vendor.e2e')",
            # Other module loaders that would do just as well.
            "import runpy\nns = runpy.run_path('vendor/e2e.py')",
            "import pkgutil\nl = pkgutil.get_loader('technocore_mcp.vendor.e2e')",
        ]
        for source in bypasses:
            with self.subTest(source=source.splitlines()[-1]):
                self.assertNotEqual(forbidden_vendor_imports(source), [],
                                    "this bypass was not detected")

    def test_the_detector_does_not_flag_the_legitimate_imports(self):
        """`vendorguard` must not be caught by a prefix match on `vendor`, and
        neither must `vendor_facade` -- both are the supported way in."""
        legitimate = [
            "from . import vendor_facade",
            "from . import vendorguard",
            "from .vendorguard import VendorAccessError, VendorIntegrityError",
            "from technocore_mcp.vendorguard import load",
            "from .routes import fetch_technocore",
            "from . import exports, labels, paths, routes",
            "import os, json, re",
            "vendor = vendor_facade()\nvendor.validate_name('jobs')",
            # Every import the package actually makes must stay clear of the
            # ban. `urllib` and `importlib` are not the same word, and an
            # ordinary getattr is not an import.
            "import urllib.parse, urllib.request, urllib.error",
            "from pathlib import Path",
            "from datetime import datetime, timezone",
            "import binascii, unicodedata, stat, shutil, io, sys",
            "value = getattr(identity, 'did', None)",
            "import os as _os\nroom_key = _os.urandom(32)",
        ]
        for source in legitimate:
            with self.subTest(source=source.splitlines()[0]):
                self.assertEqual(forbidden_vendor_imports(source), [],
                                 "a legitimate import was flagged")

    def test_vendorguard_is_the_one_file_that_may_use_import_machinery(self):
        text = (PACKAGE / "vendorguard.py").read_text(encoding="utf-8")
        self.assertNotEqual(forbidden_vendor_imports(text), [],
                            "vendorguard no longer loads the vendored client; "
                            "if that moved, the exemption must move with it")


class ToolSurface(unittest.TestCase):
    def test_no_tool_takes_a_forbidden_argument(self):
        for tool in tools.TOOLS:
            for argument in tool["inputSchema"]["properties"]:
                self.assertNotIn(argument.lower(), FORBIDDEN_ARGUMENTS,
                                 f"{tool['name']} takes {argument!r}")

    def test_no_tool_publishes_or_returns_a_write_url(self):
        listed = json.dumps(tools.public_tools()).lower()
        for fragment in ("/set/", "include_write_url", "publish_note", "confirm"):
            self.assertNotIn(fragment, listed)

    def test_capabilities_reports_the_unpublished_specs_instead_of_failing_stubs(self):
        payload = tools.capabilities(vendor_facade())
        self.assertIn("faucet", payload["unavailable"])
        self.assertNotIn("technocore_claim_faucet", [t["name"] for t in tools.TOOLS])


class RouteBoundary(unittest.TestCase):
    def test_no_template_is_a_write_route(self):
        for route, (pattern, _) in routes.TEMPLATES.items():
            self.assertTrue(pattern.startswith("/"), route)
            self.assertNotIn("/set/", pattern, route)

    def test_a_key_carrying_a_separator_is_refused(self):
        """`/kv/<ns>/<key>` and `/kv/<ns>/<key>/set/<value>` are adjacent routes.

        Without NAME_RE on the segment, a read tool becomes the publish route --
        on the correct host, so the origin check would pass it.
        """
        for bad in ("x/set/pwned", "x/../y", "x%2Fset%2Fy", "x/", "/x"):
            with self.assertRaises((RouteError, ValueError), msg=bad):
                routes.build_url(routes.ROUTE_KV_READ, {"ns": "did", "key": bad})

    def test_a_room_that_could_move_the_authority_is_refused(self):
        for bad in (".evil.com", "@evil.com", "evil.com/x", "..", "a" * 64, ""):
            with self.assertRaises((RouteError, ValueError), msg=bad):
                routes.build_url(routes.ROUTE_ROOM, {"room": bad})

    def test_verify_url_refuses_everything_that_is_not_our_origin(self):
        host = "technocore.chat"
        routes.verify_url("https://technocore.chat/r/jobs", host)  # the good case
        for bad in (
            "https://technocore.chat.evil.com/r/jobs",   # suffix, no trailing slash in BASE
            "https://technocore.chat@evil.com/x",        # host becomes userinfo
            "http://technocore.chat/r/jobs",             # downgraded scheme
            "https://technocore.chat:8443/r/jobs",       # different endpoint
            "https://technocore.chat./r/jobs",           # trailing dot
            "https://evil.com/r/jobs",
        ):
            with self.assertRaises(OriginError, msg=bad):
                routes.verify_url(bad, host)

    def test_the_destination_is_not_a_parameter_of_anything(self):
        """An earlier revision let `build_url` take a `host` "for tests".

        That made the origin check self-consistent: it verified the URL against
        the host the caller had just supplied, so it could not fail. A parameter
        that moves the boundary is exactly what this design keeps getting wrong,
        and a test that passes because of one is worse than no test.
        """
        import inspect
        for function in (routes.build_url, routes.fetch_technocore):
            self.assertNotIn("host", inspect.signature(function).parameters,
                             f"{function.__name__} lets its caller pick the host")

    def test_every_assembled_url_is_checked_after_it_is_built(self):
        """1 and 2 inspect inputs and can be under-written -- they were. 3 looks
        at the result, so it still stops a gap upstream of it. Prove it runs."""
        seen = []
        original = routes.verify_url
        routes.verify_url = lambda url, host: seen.append((url, host)) or original(url, host)
        try:
            url = routes.build_url(routes.ROUTE_KV_READ, {"ns": "did", "key": "abc"})
        finally:
            routes.verify_url = original
        self.assertEqual(seen, [(url, routes.configured_host())])

    def test_an_unknown_route_or_query_parameter_is_refused(self):
        with self.assertRaises(RouteError):
            routes.build_url("anything_else", {})
        with self.assertRaises(RouteError):
            routes.build_url(routes.ROUTE_ROOMS, {}, {"callback": "x"})

    def test_query_values_are_coerced_not_passed_through(self):
        url = routes.build_url(routes.ROUTE_ROOM, {"room": "jobs"},
                               {"since": 5, "limit": 200, "format": "json"})
        self.assertEqual(urllib.parse.urlsplit(url).hostname, routes.configured_host())
        with self.assertRaises(RouteError):
            routes.build_url(routes.ROUTE_ROOM, {"room": "jobs"}, {"wait": 99})
        with self.assertRaises(RouteError):
            routes.build_url(routes.ROUTE_ROOM, {"room": "jobs"}, {"format": "xml"})

    def test_a_configured_host_that_is_not_a_plain_hostname_is_refused(self):
        import os
        previous = os.environ.get("TECHNOCORE_MCP_HOST")
        try:
            for bad in ("technocore.chat:8443", "https://technocore.chat",
                        "a@b.com", "technocore.chat/x", "technocore.chat."):
                os.environ["TECHNOCORE_MCP_HOST"] = bad
                with self.assertRaises(OriginError, msg=bad):
                    routes.configured_host()
        finally:
            os.environ.pop("TECHNOCORE_MCP_HOST", None)
            if previous is not None:
                os.environ["TECHNOCORE_MCP_HOST"] = previous


if __name__ == "__main__":
    unittest.main()
