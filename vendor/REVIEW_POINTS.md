# Review points for an upstream update

The startup hash tells you *that* `e2e.py` changed. It cannot tell you *what*
changed. These are the places where a change alters something this package
depends on for safety, so read the diff at these points before bumping
`UPSTREAM.txt`.

## 1. URL construction inside the allowlisted network function

`say_signed()` is allowlisted (see `technocore_mcp/vendorguard.py`). It is
allowed **not** because it avoids the raw `get()` primitive -- it calls it --
but because of *how* it builds the destination:

```python
url = (f"{BASE}/r/{room}/say-signed/{identity['did']}/{b64u(signature)}/"
       f"{nonce}/{urllib.parse.quote(swept, safe='')}")
```

Two properties carry the safety, and both must survive an update:

- the character immediately after `BASE` is a literal `/`. `BASE` has no
  trailing slash, so without that literal the authority can be moved by the
  next segment (`".evil.com/..."` concatenates into a different host).
- `room` has passed `validate_name()` (`NAME_RE = ^[a-z0-9][a-z0-9_-]{0,47}$`)
  before it reaches the string, so caller bytes cannot introduce `/`, `@` or a
  scheme.

`read_room()` had the same shape and is no longer allowlisted -- this package
reads through its own `fetch_technocore` instead -- but if you re-allow it,
the same two properties are what you are checking.

**If either property changes upstream, this package must stop calling that
function**, not adapt to it.

## 2. The CLI layer stays unreachable

`cmd_seal()` carries `--key-is-corroborated`, which suppresses the key
substitution warning. This package never reaches it: it calls `seal_room_key()`,
the pure function, and emits the warning itself, always.

If an upstream change moves warning suppression (or any other trust signal)
*down* into a function on the allowlist, that function must come off the
allowlist. Check that `seal_room_key()` is still purely "seal these bytes".

## 3. New CLI commands are denied by default

The allowlist is closed: a new `cmd_*` upstream is unreachable without an
explicit addition here. Nothing to do on an update -- this note exists so the
default is not mistaken for an oversight.

## 4. `note_urls()` stays denied

It builds `/kv/<shard>/<key>`, which is one segment away from the
`/kv/.../set/<value>` write route. This package derives note coordinates from
`fingerprint(did)` itself and never returns a write URL. If `note_urls()` gains
callers on the allowlist, that is a regression.

## 5. Constants read directly

`BASE`, `MESSAGE_CAP` and `NAME_RE` are read from the vendored module.
`BASE`'s host is compared against this package's configured host at startup and
a mismatch is fatal -- so that reads (ours) and signed writes (the vendor's)
cannot silently address different servers.
