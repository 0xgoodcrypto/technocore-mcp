"""Tool behaviour that needs a key on disk, and the export write boundary.

A throwaway identity is generated into a temporary home. Tests may reach the
vendored module directly -- the allowlist governs what `technocore_mcp` may
call, and this is not `technocore_mcp`.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from technocore_mcp import exports, paths, tools, vendor_facade, vendorguard

_TEMP = None


def setUpModule():
    global _TEMP
    _TEMP = tempfile.TemporaryDirectory()
    home = Path(_TEMP.name)
    os.environ["TECHNOCORE_MCP_HOME"] = str(home)
    identity = vendorguard.load()._module.create_identity()
    (home / "identity.json").write_text(json.dumps(identity), encoding="utf-8")
    if os.name != "nt":
        (home / "identity.json").chmod(0o600)
    tools._identity_cache.clear()


def tearDownModule():
    tools._identity_cache.clear()
    os.environ.pop("TECHNOCORE_MCP_HOME", None)
    _TEMP.cleanup()


class Identity(unittest.TestCase):
    def test_whoami_returns_no_private_material(self):
        payload = tools.whoami(vendor_facade())
        rendered = json.dumps(payload)
        self.assertIn("did:key:", payload["did"])
        for secret in ("ed25519_private_key_hex", "x25519_private_key_hex", "private_key"):
            self.assertNotIn(secret, rendered)

    def test_did_note_returns_coordinates_and_never_a_url(self):
        payload = tools.did_note(vendor_facade())
        rendered = json.dumps(payload)
        self.assertEqual(sorted(payload["sharded"]), ["key", "namespace"])
        self.assertNotIn("/set/", rendered)
        self.assertNotIn("https://", rendered)
        self.assertNotIn("http://", rendered)

    def test_did_note_coordinates_are_derived_from_the_did(self):
        vendor = vendor_facade()
        payload = tools.did_note(vendor)
        fp = vendor.fingerprint(tools.whoami(vendor)["did"])
        self.assertEqual(payload["sharded"]["namespace"], f"did-{fp[:2]}")
        self.assertEqual(payload["sharded"]["key"], fp[2:])


class Envelopes(unittest.TestCase):
    def test_seal_always_reports_that_corroboration_is_required(self):
        vendor = vendor_facade()
        recipient = tools.whoami(vendor)["x25519_public_key_b64url"]
        payload = tools.seal_room_key(vendor, recipient, room="test-seal-room")
        self.assertTrue(payload["key_corroboration_required"])
        self.assertIn("corroborate", payload["key_corroboration_warning"].lower())

    def test_a_sealed_envelope_round_trips_and_the_key_matches(self):
        vendor = vendor_facade()
        recipient = tools.whoami(vendor)["x25519_public_key_b64url"]
        sealed = tools.seal_room_key(vendor, recipient, room="test-round-trip")
        opened = tools.open_sealed(vendor, sealed["line"])
        self.assertTrue(opened["addressed_to_this_identity"])
        self.assertEqual(opened["room"], "test-round-trip")
        self.assertEqual(opened["room_key_hex"], sealed["room_key_hex"])

    def test_an_envelope_for_someone_else_says_so_without_guessing(self):
        vendor = vendor_facade()
        other = vendorguard.load()._module.create_identity()
        sealed = tools.seal_room_key(
            vendor, other["x25519_public_key_b64url"], room="not-ours")
        opened = tools.open_sealed(vendor, sealed["line"])
        self.assertFalse(opened["addressed_to_this_identity"])
        self.assertNotIn("room", opened)

    def test_ciphertext_round_trips_and_stays_labelled_untrusted(self):
        vendor = vendor_facade()
        sealed = tools.seal_room_key(
            vendor, tools.whoami(vendor)["x25519_public_key_b64url"])
        wire = tools.encrypt_line(vendor, sealed["room_key_hex"], "hello there")
        plain = tools.decrypt_line(vendor, sealed["room_key_hex"], wire["line"])
        self.assertEqual(plain["text"], "hello there")
        self.assertEqual(plain["trust"], "untrusted")

    def test_a_bad_room_key_is_a_refusal_not_a_traceback(self):
        vendor = vendor_facade()
        for bad in ("not-hex", "aa", "", "z" * 64):
            with self.assertRaises(tools.ToolError, msg=bad):
                tools.encrypt_line(vendor, bad, "x")


class ExportBoundary(unittest.TestCase):
    def test_the_file_lands_in_the_server_owned_directory(self):
        written = exports.write_export("jobs", '{"seq":1}\n', "gen-1")
        self.assertEqual(Path(written["path"]).parent, paths.exports_dir().resolve())
        self.assertTrue(Path(written["path"]).exists())

    def test_a_room_name_that_would_escape_the_directory_is_refused(self):
        """Belt and braces: `room` arrives already NAME_RE-checked as a route
        segment, so this can only happen if that check is bypassed. The
        containment test re-checks the resolved result anyway -- same shape as
        re-parsing an assembled URL rather than trusting the inputs."""
        for bad in ("../escape", "../../etc/passwd", "sub/dir"):
            with self.assertRaises(exports.ExportError, msg=bad):
                exports.write_export(bad, "{}\n", "g")

    def test_an_export_over_the_size_cap_is_refused(self):
        original = exports.MAX_EXPORT_BYTES
        exports.MAX_EXPORT_BYTES = 16
        try:
            with self.assertRaises(exports.ExportError):
                exports.write_export("jobs", "x" * 64, "g")
        finally:
            exports.MAX_EXPORT_BYTES = original

    def test_an_existing_file_is_never_overwritten(self):
        written = exports.write_export("jobs", '{"seq":1}\n', "gen-2")
        target = Path(written["path"])
        with self.assertRaises(exports.ExportError):
            exports._write_at(target, b"replacement")
        self.assertEqual(target.read_text(encoding="utf-8"), '{"seq":1}\n')

    def test_a_generation_header_off_the_wire_cannot_shape_the_filename(self):
        written = exports.write_export("jobs", "{}\n", "../../evil")
        self.assertEqual(Path(written["path"]).parent, paths.exports_dir().resolve())
        self.assertIn("gen-unparsed", Path(written["path"]).name)

    def test_the_export_tool_has_no_destination_argument(self):
        schema = tools.BY_NAME["technocore_export_room"]["inputSchema"]
        self.assertEqual(sorted(schema["properties"]), ["inline", "room"])


if __name__ == "__main__":
    unittest.main()
