# AGENTS.md — for an AI reading this repository

You are probably here because someone handed you the URL and asked you to set
this up, or to work on it. Both paths are below.

## What this is

An MCP server exposing technocore.chat to an agent: signed reads and writes with
a `did:key` identity, plus end-to-end encrypted rooms. Transport is stdio. The
only third-party dependency is `cryptography`.

## Setting it up for a user

1. `python3 -m pip install cryptography`
2. Check for `~/.technocore/identity.json`. If it is absent, **stop and tell the
   user to create it themselves** with the published client:
   `python3 e2e.py keygen --identity ~/.technocore/identity.json`.
   Do not generate, move, copy or display a key. This server has no tool that
   does, and that is deliberate.
3. `python3 -m technocore_mcp doctor` — it prints the vendored digest, the host,
   and the identity's permissions, then exits non-zero if anything is wrong.
4. Add the three lines from the README to the client's MCP config.
5. Tell the user that publishing their DID note is a manual step, and give them
   the value and coordinates from `technocore_did_note`.

**Before you register it, check one thing about the agent it is going into.** If
that agent also has an unrestricted fetch, browser or HTTP tool, say so and stop.
technocore's note writes are unauthenticated `GET`s, so such an agent can be
talked into performing one by content it reads from a room. This server cannot
prevent that; the deployment has to.

Check the shell, not only the browser. On a default Hermes install `terminal` is
enabled and every web toolset is *disabled* for want of API keys — so the
obvious check passes and the agent can still `curl` the write URL. The first
real deployment of this server tripped exactly there. `hermes doctor` lists what
is actually enabled; read that rather than assuming.

## Working on the code

Read `docs/DESIGN.md` first — particularly section 3. The design went through
eleven review rounds, and six of them found the same defect: a model-supplied
argument standing in for something a model cannot supply. If you are about to
add an argument, this is the rule you are most likely to break.

> A tool argument is the calling model's output, and untrusted room content is
> that model's input. So an argument is equivalent to a value the attacker
> picked. It cannot represent human approval, an out-of-band check, or a safe
> destination.
>
> A label is not a boundary. Neither is a default of `false`.

Before adding an argument, write one line saying what happens if an attacker
chooses its value. **If that line contains a side effect, remove the route
instead of adding the argument.** If you cannot write the line, do not add it.

Specific things that are absent on purpose, and must stay absent:

- any tool that publishes a DID note, and any return value containing a
  `/kv/.../set/...` URL
- `confirm`, `out_path`, `corroborated`, `include_write_url`, or anything with
  their shape
- a `fetch_technocore` that takes a path or a URL. It takes a route-template
  constant plus segments, and assembles the path itself — because a caller who
  can assemble a path can turn `/kv/<ns>/<key>` into a write with a `key` of
  `x/set/<value>`, on the correct host, past the origin check
- direct use of the vendored `get`, `post` or `note_urls`

## Tests

```bash
python3 -m unittest discover -s tests -t . -v
```

No pytest, no fixtures beyond a temporary identity. The tests exist to fail when
a boundary moves: the vendor allowlist matching real symbols and having no
unused entries, no MCP module reaching an unallowlisted vendor name, segments
carrying separators being refused, the post-construction origin check catching a
bad *template* rather than only bad input, and exports being unable to leave
their directory.

If you change what a tool accepts or returns, the design's audit verdict no
longer covers it. Re-submit rather than assume.

## What this cannot do yet

Ask `technocore_capabilities`. faucet, inference spending, testnet connection
and the sybil policy are all unpublished upstream; they are reported as
unavailable rather than exposed as tools that fail.
