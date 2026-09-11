"""The MCP wire surface. No network: nothing here reaches past argument checking."""

import io
import json
import unittest

from technocore_mcp import server, tools, vendor_facade


def _handle(message):
    return server.handle(vendor_facade(), message)


class Handshake(unittest.TestCase):
    def test_initialize_echoes_a_version_we_support(self):
        for asked in server.SUPPORTED_PROTOCOLS:
            reply = _handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                             "params": {"protocolVersion": asked}})
            self.assertEqual(reply["result"]["protocolVersion"], asked)

    def test_an_unknown_version_falls_back_rather_than_failing(self):
        reply = _handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                         "params": {"protocolVersion": "1999-01-01"}})
        self.assertIn(reply["result"]["protocolVersion"], server.SUPPORTED_PROTOCOLS)

    def test_the_handshake_says_read_results_are_untrusted(self):
        reply = _handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
        self.assertIn("untrusted", reply["result"]["instructions"].lower())

    def test_a_notification_gets_no_response(self):
        self.assertIsNone(_handle({"jsonrpc": "2.0", "method": "notifications/initialized"}))

    def test_an_unsupported_method_is_an_error_not_a_crash(self):
        reply = _handle({"jsonrpc": "2.0", "id": 7, "method": "resources/list"})
        self.assertEqual(reply["error"]["code"], server.METHOD_NOT_FOUND)


class ToolsList(unittest.TestCase):
    def test_listing_carries_no_handlers(self):
        reply = _handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        for tool in reply["result"]["tools"]:
            self.assertNotIn("handler", tool)
            self.assertEqual(tool["inputSchema"]["additionalProperties"], False)

    def test_every_advertised_tool_is_callable(self):
        """Nothing listed that always fails: unavailability is reported by
        technocore_capabilities instead, so an agent reads it once rather than
        retrying a stub."""
        reply = _handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        for tool in reply["result"]["tools"]:
            self.assertIn(tool["name"], tools.BY_NAME)


class Arguments(unittest.TestCase):
    def _call(self, name, arguments):
        reply = _handle({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                         "params": {"name": name, "arguments": arguments}})
        return json.loads(reply["result"]["content"][0]["text"]), reply["result"]["isError"]

    def test_an_unknown_argument_is_rejected_rather_than_ignored(self):
        """Silently dropping an unexpected argument is how a removed control
        comes back: the caller believes it passed, and nothing says otherwise."""
        for argument in ("confirm", "out_path", "corroborated", "include_write_url"):
            payload, is_error = self._call("technocore_did_note", {argument: True})
            self.assertTrue(is_error, argument)
            self.assertIn("unknown argument", payload["error"])

    def test_a_missing_required_argument_is_named(self):
        payload, is_error = self._call("technocore_read_room", {})
        self.assertTrue(is_error)
        self.assertIn("room", payload["error"])

    def test_an_unknown_tool_is_an_error_result_not_an_exception(self):
        payload, is_error = self._call("technocore_publish_note", {})
        self.assertTrue(is_error)
        self.assertIn("no such tool", payload["error"])

    def test_a_bad_room_name_is_refused_before_any_request(self):
        payload, is_error = self._call("technocore_read_room", {"room": "../evil"})
        self.assertTrue(is_error)

    def test_capabilities_needs_no_arguments_and_names_the_precondition(self):
        payload, is_error = self._call("technocore_capabilities", {})
        self.assertFalse(is_error)
        self.assertIn("fetch", payload["deployment_precondition"])


class Transport(unittest.TestCase):
    def _drive(self, payload):
        stdout = io.StringIO()
        server.serve(io.StringIO(payload), stdout)
        return [json.loads(line) for line in stdout.getvalue().splitlines()]

    def test_malformed_json_does_not_take_the_loop_down(self):
        replies = self._drive('not json\n{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
        self.assertEqual(replies[0]["error"]["code"], server.PARSE_ERROR)
        self.assertEqual(replies[1]["result"], {})

    def test_valid_json_that_is_not_an_object_is_refused_and_the_loop_survives(self):
        """Valid JSON is not necessarily a request.

        An array or a scalar parses cleanly and then has no `.get`. Before the
        dict check, that raised inside `handle` *and* again inside the exception
        handler -- which called `message.get("id")` on the same non-object -- so
        the second failure escaped `serve` and ended the loop the handler exists
        to protect. One well-formed line could stop the transport.
        """
        for payload in ("[]", '[{"jsonrpc":"2.0","id":1,"method":"ping"}]',
                        '"a string"', "123", "12.5", "null", "true"):
            with self.subTest(payload=payload):
                replies = self._drive(
                    payload + '\n{"jsonrpc":"2.0","id":9,"method":"ping"}\n')
                self.assertEqual(len(replies), 2,
                                 "the loop stopped instead of continuing")
                self.assertEqual(replies[0]["error"]["code"], server.INVALID_REQUEST)
                self.assertIsNone(replies[0]["id"])
                # The next request still works: the transport is still up.
                self.assertEqual(replies[1]["id"], 9)
                self.assertEqual(replies[1]["result"], {})

    def test_a_batch_array_says_batches_are_unsupported(self):
        replies = self._drive('[{"jsonrpc":"2.0","id":1,"method":"ping"}]\n')
        self.assertIn("batch", replies[0]["error"]["message"].lower())


if __name__ == "__main__":
    unittest.main()
