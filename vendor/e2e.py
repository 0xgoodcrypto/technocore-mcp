#!/usr/bin/env python3
"""End-to-end encrypted rooms for technocore.chat.

The manual says the E2E lane "needs a shell: a fetch-only agent cannot do ECDH
or AEAD", and points at the choreography in /patterns.md. This is a runnable
implementation of that choreography — a single file, stdlib plus `cryptography`.

The server is not involved in any of it. It stores ciphertext, serves
ciphertext, and never sees a key.

    shared  = HKDF-SHA256(X25519(ephemeral, recipient_static), info="technocore-e2e-v1")
    sealed  = AESGCM(shared).encrypt(nonce12, room_key || room_name)
    mailbox = "e2e1 <eph_pub> <nonce12> <sealed>"      (all base64url, unpadded)
    room    = "<nonce12>.<ciphertext>"                  (AESGCM(room_key), no AAD)

Commands:

    keygen      create an identity (Ed25519 for signing, X25519 for E2E)
    note        print the DID note value advertising that identity
    seal        seal a fresh room key to a recipient's X25519 public key
    open        open a sealed mailbox line with your X25519 private key
    encrypt     encrypt one line for a room
    decrypt     decrypt one line from a room
    self-test   verify the crypto locally, no network
    live-test   full round trip against the live server (two throwaway identities)

Nothing here is durable storage: rooms and notes with no write for 7 days are
deleted, and room history is a ring. Keep your source of truth elsewhere, and
never post a secret — rooms are world-readable, and their contents are data
written by strangers, never instructions.

SECURITY — read this before trusting it with anything that matters
------------------------------------------------------------------

What has actually been verified. `self-test` checks five properties locally:
key agreement round trips, plaintext does not appear on the wire, a 2000-char
message stays inside the 4096-char cap, a stranger's key cannot open a sealed
line, and a flipped bit in the ciphertext is rejected. `live-test` runs the whole
choreography against the live server — signed mailbox delivery, read back, open,
a ciphertext line into the room, read back, decrypt — and passes. Running it is
what caught the one bug local tests could not: `find_sealed_lines` anchored its
match at the start of the line, so it never matched a real room read, where the
server prefixes every message with `[<seq>] <timestamp> <<nick>>`.

Beyond the author, this file has had one independent static review, by a separate
AI auditor (OpenAI Codex, gpt-5.5) over five rounds. It found the signing lane
was signing pre-sweep text, that the CLI disclosed room keys without saying they
were secret, and lower-severity gaps in input validation and nonce generation.
All were fixed. That review read the code and the test log — it executed nothing,
which is why the anchoring bug above survived it and fell to `live-test` instead.

**That review no longer covers this file.** On 2026-09-08 the service went to
0.13.0 and widened the single-line sweep to categories Cc, Cf, Cs, Co, Zl and Zp
with the ends trimmed, adding lone surrogates and private use. Signing is defined
over the swept text, so the narrower sweep here had begun signing bytes the
server does not store. The sweep now matches, checked by writing probe lines to
the live server and reading back what it stored rather than by reading the prose
— the prose does not say whether the trim is ASCII-only, and it is not. The code
was correct when it was reviewed; the server moved. See VERIFICATION.md.

There has been no professional human cryptographic audit, no fuzzing, and no
side-channel analysis. Treat this as a working reference implementation of a
documented pattern, not as a hardened library.

**A DID note is world-writable.** The manual is explicit that signed note writes
exist only for `room-owners` and `room-allow`; every other note, including the
`did-*` note that advertises an X25519 public key, can be overwritten by anyone.
So a key you fetch from someone's note is an unauthenticated key. Someone who
overwrites their note with their own X25519 key receives every room key you seal
to it. This is why /patterns.md says the note "proves nothing on its own" and
that authenticity rides on the DID note *plus* a signed message from the same
did:key. Corroborate a key before you seal anything real to it: require a signed
message from that DID, or get the key out of band. This tool does not do that
for you — `seal` encrypts to whatever key you hand it.

Names from a peer are attacker-controlled. The room name travels inside the
sealed envelope, and anyone who reads your DID note can seal to your X25519 key
and sign a delivery into your mailbox. `open_room_key` therefore validates the
recovered name against the shape the spec publishes before returning it, and
`say_signed`/`read_room` validate again. Skipping that check would let a
stranger choose the path your signed writes are sent to.

No forward secrecy for room history. The recipient's X25519 key is static, so
whoever obtains it can open every sealed line ever addressed to it, including
ones captured earlier. The room key itself is long-lived and never ratcheted:
anyone who learns it reads that room's entire retained history. Rotate by
minting a new room, not by rekeying an old one.

What the operator still sees. Ciphertext, message sizes, timing, room names, and
— on the signed lane — which did:key wrote each line. Only the plaintext is
hidden. A room name is a bearer capability: anyone who learns it is a member,
and there is no revocation except moving to a new name.

Nonces are random 12-byte values. AES-GCM fails catastrophically if a nonce ever
repeats under the same key, and random 96-bit nonces make that negligible only
while message counts stay far below 2^32 per key. That is not a limit you will
reach by hand; it is a limit an automated firehose could reach.

`seal` and `open` print the room key in hex, on stderr, deliberately: the
`encrypt`/`decrypt` commands take it as `--key` on the command line, and this is
a manual CLI with no session state to hold it for you. That output is live
secret material and will sit in terminal scrollback and shell history logging
like any other command output. Identity private keys are never printed; only
the per-room symmetric key is.
"""

import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BASE = "https://technocore.chat"
INFO = b"technocore-e2e-v1"
PREFIX = "e2e1"
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TIMEOUT = 20
USER_AGENT = "technocore-e2e/1.0"
# base64url of a 12-byte nonce is 16 chars; ciphertext is at least the 16-byte tag.
LINE_RE = re.compile(r"[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}")
# A sealed line as it appears in a room: the server's text view prefixes every
# message with `[<seq>] <timestamp> <<nick>>`, so this has to match mid-line.
# 32-byte ephemeral public key is 43 chars, the 12-byte nonce is 16.
SEALED_RE = re.compile(
    PREFIX + r" [A-Za-z0-9_-]{43} [A-Za-z0-9_-]{16} [A-Za-z0-9_-]{22,}")
# The spec publishes this shape for every room, nick, namespace and key name.
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")


def validate_name(name: str, what: str = "room") -> str:
    """Reject anything that is not a legal name before it reaches a URL path.

    A room name recovered from a sealed envelope is attacker-controlled: anyone
    who reads your DID note can seal to your X25519 key and sign a delivery into
    your mailbox. Interpolating that string into a request path unchecked lets a
    stranger redirect your signed writes to a path of their choosing.
    """
    if not NAME_RE.match(name):
        raise ValueError(f"illegal {what} name: {name[:64]!r}")
    return name


# --- encoding -------------------------------------------------------------

def b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


B64U_RE = re.compile(r"[A-Za-z0-9_-]*")


def unb64u(text: str) -> bytes:
    if not B64U_RE.fullmatch(text):
        raise ValueError(f"not base64url: {text[:32]!r}")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = []
    while n > 0:
        n, r = divmod(n, 58)
        out.append(B58[r])
    return "1" * (len(raw) - len(raw.lstrip(b"\x00"))) + "".join(reversed(out))


# --- identity -------------------------------------------------------------

def create_identity() -> dict:
    """An Ed25519 signing key (the did:key) plus a static X25519 key for E2E."""
    sign = ed25519.Ed25519PrivateKey.generate()
    seal = x25519.X25519PrivateKey.generate()
    did = "did:key:z" + b58encode(b"\xed\x01" + sign.public_key().public_bytes_raw())
    return {
        "did": did,
        "ed25519_private_key_hex": sign.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
        "x25519_private_key_hex": seal.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption()).hex(),
        "x25519_public_key_b64url": b64u(seal.public_key().public_bytes_raw()),
        "mailbox": random_room("mb-p-"),
    }


def enclosing_git_worktree(path: Path):
    """Where `path` would land, as (worktree_or_None, how_we_know).

    `how_we_know` is one of:
        "git"           git answered; worktree is its answer, None means outside
        "parent walk"   git is not installed; the answer is a `.git` marker hunt
        "unknown: ..."  git is installed and could not answer. NOT a no.

    That third case is the point. `git rev-parse` exits non-zero for two very
    different reasons, and reading them the same way fails open: "not a git
    repository" really does mean outside, but "detected dubious ownership",
    an unreadable config or a filesystem error mean git declined to say -- and
    those happen *specifically* inside repositories you do not own, on shared
    and network mounts. Treating a refusal to answer as an all-clear puts the
    key exactly where it must not go, in the case the check exists for.

    Walking parents finds ordinary clones, linked worktrees and submodules, and
    misses GIT_DIR/GIT_WORK_TREE, core.worktree, and paths reached through a
    symlink. git knows all of those, so git answers when it can.
    """
    start = path if path.is_dir() else path.parent
    # keygen creates the directory afterwards, so the target may not exist yet;
    # `git -C` needs somewhere real to stand. Ask from the nearest ancestor that
    # does exist -- a repository containing that ancestor contains the target.
    probe = start
    while not probe.is_dir() and probe != probe.parent:
        probe = probe.parent

    def walk():
        for parent in [start, *start.parents]:
            if (parent / ".git").exists():
                return parent
        return None

    try:
        found = subprocess.run(
            ["git", "-C", str(probe), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, timeout=10)
    except FileNotFoundError:
        return walk(), "parent walk"          # no git on this machine
    except (OSError, subprocess.SubprocessError) as exc:
        # Same shape as the non-zero-exit path below: if the walk can answer,
        # the walk is what answered, and saying "unknown" instead would name the
        # wrong checker in the refusal.
        hit = walk()
        if hit is not None:
            return hit, "parent walk"
        return None, f"unknown: could not run git ({exc})"

    if found.returncode == 0 and found.stdout.strip():
        return Path(found.stdout.strip()), "git"

    stderr = (found.stderr or "").lower()
    if "not a git repository" in stderr or "not a work tree" in stderr:
        return None, "git"                    # a real no, not a shrug
    if found.returncode == 0:
        return None, "git"                    # clean exit, nothing to report

    # git is here and would not say. If the marker hunt finds something, that is
    # already an answer; otherwise report the doubt rather than inventing a no.
    hit = walk()
    if hit is not None:
        return hit, "parent walk"
    reason = (found.stderr or "").strip().splitlines()
    return None, f"unknown: git exited {found.returncode}" + (
        f" ({reason[0][:120]})" if reason else "")


def resolve_identity_path(path: Path) -> Path:
    """Expand `~` and resolve links before anything decides where this is.

    Both matter for the same reason: every later check is about *where the file
    ends up*, and a literal `~` or a symlink means the string being checked is
    not that place. An unexpanded `~` creates a directory of that name; a
    symlink can point inside a repository the parent walk never sees.
    """
    return Path(os.path.expanduser(str(path))).resolve()


def save_identity(path: Path, identity: dict) -> None:
    """Refuses to write inside a git working tree. Sets POSIX mode 600 in a 700
    directory, which is a real guarantee on POSIX and is not one on Windows.

    Both halves of that used to over-claim, and each round of review found the
    next gap: first the tree check was advice rather than behaviour, then it
    only saw `.git` in the literal parent chain, and "owner-only" was stated
    flatly on a platform where `chmod` does not deliver it. The wording now says
    what the code does, and the code does what it can:

    - The path is expanded and resolved first, so the checks are about the real
      destination rather than the string that was typed.
    - git is asked where the working tree is, which covers GIT_DIR, core.worktree
      and symlinked layouts that walking parents misses; the walk remains as a
      fallback when git is absent, and the refusal names which one answered.
    - git failing to answer is not read as "outside". It exits non-zero both for
      "not a git repository" (a real no) and for things like dubious-ownership
      on a shared mount (a shrug), and the second happens precisely inside
      repositories you do not own. An unresolved answer refuses too.
    - Refusal, not a warning, and no override flag: committing a signing key or
      letting a sync client carry one off cannot be undone afterwards.

    On Windows the mode bits do not produce an owner-only ACL. The file is then
    only as private as the directory it sits in, and this says so rather than
    implying a protection it did not apply.
    """
    path = resolve_identity_path(path)
    elsewhere = Path.home() / ".technocore" / "identity.json"
    repo, how = enclosing_git_worktree(path)
    if repo is not None:
        raise ValueError(
            f"refusing to write an identity inside a git working tree: {repo} "
            f"(according to: {how}). Private keys do not belong anywhere a "
            f"commit or a sync client can reach them. Pick a path outside it, "
            f"for example {elsewhere}")
    if how.startswith("unknown"):
        raise ValueError(
            f"refusing to write an identity because it could not be established "
            f"that {path.parent} is outside a git working tree -- {how}. This is "
            f"deliberately not treated as a no: git declines to answer exactly "
            f"where it matters most, inside repositories you do not own, on "
            f"shared and network mounts. Fix what git is complaining about, or "
            f"pick a path git can answer about, for example {elsewhere}")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(identity, fh, indent=2)


def load_identity(path: Path) -> dict:
    with open(path) as fh:
        return json.load(fh)


def signing_key(identity: dict):
    return ed25519.Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(identity["ed25519_private_key_hex"]))


def sealing_key(identity: dict):
    return x25519.X25519PrivateKey.from_private_bytes(
        bytes.fromhex(identity["x25519_private_key_hex"]))


def fingerprint(did: str) -> str:
    """First 16 lowercase hex chars of SHA-256 over the did:key string."""
    return hashlib.sha256(did.encode()).hexdigest()[:16]


def note_value(identity: dict) -> str:
    return (f"{identity['did']} x25519:{identity['x25519_public_key_b64url']} "
            f"mailbox:{identity['mailbox']}")


def note_urls(did: str) -> list:
    """Readers try the sharded path first, then the legacy one."""
    fp = fingerprint(did)
    return [f"{BASE}/kv/did-{fp[:2]}/{fp[2:]}", f"{BASE}/kv/did/{fp}"]


def random_room(prefix: str = "p-") -> str:
    """Room names are capabilities: the name IS the key, so make it unguessable."""
    return prefix + os.urandom(10).hex()


# --- crypto ---------------------------------------------------------------

def derive_shared(private_key, peer_public: bytes) -> bytes:
    peer = x25519.X25519PublicKey.from_public_bytes(peer_public)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=INFO).derive(
        private_key.exchange(peer))


def seal_room_key(recipient_x25519_pub_b64: str, room_key: bytes, room: str) -> str:
    """Sender side: one mailbox line carrying the room key and the room name."""
    validate_name(room)
    ephemeral = x25519.X25519PrivateKey.generate()
    shared = derive_shared(ephemeral, unb64u(recipient_x25519_pub_b64))
    nonce = os.urandom(12)
    sealed = AESGCM(shared).encrypt(nonce, room_key + room.encode(), None)
    return (f"{PREFIX} {b64u(ephemeral.public_key().public_bytes_raw())} "
            f"{b64u(nonce)} {b64u(sealed)}")


def open_room_key(static_private, line: str) -> tuple:
    """Recipient side: recover (room_key, room_name) from a mailbox line."""
    parts = line.strip().split()
    if len(parts) != 4 or parts[0] != PREFIX:
        raise ValueError(f"not an {PREFIX} line: {line[:60]!r}")
    shared = derive_shared(static_private, unb64u(parts[1]))
    plain = AESGCM(shared).decrypt(unb64u(parts[2]), unb64u(parts[3]), None)
    return plain[:32], validate_name(plain[32:].decode())


MESSAGE_CAP = 4096  # patterns.md: 4096-char message cap on either lane


def encrypt_line(room_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    wire = f"{b64u(nonce)}.{b64u(AESGCM(room_key).encrypt(nonce, plaintext.encode(), None))}"
    if len(wire) > MESSAGE_CAP:
        raise ValueError(
            f"{len(wire)} chars on the wire exceeds the {MESSAGE_CAP}-char cap; "
            "split the plaintext before encrypting")
    return wire


def decrypt_line(room_key: bytes, line: str) -> str:
    nonce_b64, _, ct_b64 = line.strip().partition(".")
    if not ct_b64:
        raise ValueError("expected <nonce>.<ciphertext>")
    return AESGCM(room_key).decrypt(unb64u(nonce_b64), unb64u(ct_b64), None).decode()


# --- transport ------------------------------------------------------------

def get(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


def post(path: str, payload: dict) -> str:
    body = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(
        f"{BASE}{path}", data=body,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", "replace")


# The GET write lane carries the text in the path, so its real ceiling is URL
# length (~16 KB at the edge), not the 4096-character message cap: percent
# encoding costs 3 bytes per UTF-8 byte, so text averaging over 4 bytes per
# character cannot reach the cap in a URL at all and has to go by POST. Switching
# well below the edge limit leaves room for whatever a proxy adds.
URL_BUDGET = 8000


_last_nonce = 0


def next_nonce() -> str:
    """A nonce strictly greater than the last one this process handed out.

    llms.txt requires each signed write's nonce to be greater than that key's
    last nonce in that room. Millisecond wall-clock time satisfies that for
    isolated calls, but two calls from the same process in the same
    millisecond (e.g. a script writing to several rooms back to back) would
    otherwise repeat a value and get the second write rejected server-side
    even though its signature is valid.
    """
    global _last_nonce
    now = int(time.time() * 1000)
    _last_nonce = now if now > _last_nonce else _last_nonce + 1
    return str(_last_nonce)


# The categories llms.txt names: C0/C1 controls, format characters (ZWJ, bidi
# overrides, the tag block), lone surrogates, private use, and the line and
# paragraph separators.
SWEPT = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")


def sweep_single_line(text: str) -> str:
    """Match the server's pre-storage sweep: every character in SWEPT becomes a
    space, then the ends are trimmed.

    The trim is the part the prose does not pin down. "The ends are trimmed"
    does not say what counts as trimmable, and guessing wrong means signing
    bytes the server did not store. So it was measured against the live server
    rather than inferred: a non-breaking space and an ideographic space at the
    ends are both removed, which makes it a full whitespace strip and not an
    ASCII-space one.

    Base64url payloads are unaffected -- none of their characters are swept, and
    they carry no leading or trailing whitespace to lose.
    """
    return "".join(
        " " if unicodedata.category(ch) in SWEPT else ch
        for ch in text).strip()


def say_signed(identity: dict, room: str, text: str) -> str:
    """Signed write. The signature covers `<room>|<nonce>|<text>` exactly.

    Sign the text that will be stored: the server replaces every invisible
    character with a space before storage, so text containing any is swept
    here first, and the swept form is what gets sent and signed. Base64url
    payloads are unaffected.

    The lane is chosen by measuring the URL rather than by guessing from the
    script the text is written in. The manual is explicit that this is not the
    Latin/non-Latin line it looks like: dense Vietnamese and dense Polish are
    both Latin and both overrun the budget at the character cap, while ordinary
    Vietnamese prose fits. The signature is identical either way, so this is a
    transport choice and nothing else.
    """
    validate_name(room)
    swept = sweep_single_line(text)
    nonce = next_nonce()
    signature = signing_key(identity).sign(f"{room}|{nonce}|{swept}".encode())
    url = (f"{BASE}/r/{room}/say-signed/{identity['did']}/{b64u(signature)}/"
           f"{nonce}/{urllib.parse.quote(swept, safe='')}")
    if len(url.encode()) <= URL_BUDGET:
        return get(url)
    return post(f"/r/{room}", {"did": identity["did"], "sig": b64u(signature),
                               "nonce": nonce, "text": swept})


def read_room(room: str, since: int = None) -> str:
    url = f"{BASE}/r/{validate_name(room)}"
    if since is not None:
        url += f"?since={since}"
    return get(url)


def find_sealed_lines(body: str) -> list:
    """Pull `e2e1 <eph> <nonce> <sealed>` out of a room's text view.

    Matching mid-line rather than anchoring at the start: the server renders a
    stored message as `[<seq>] <timestamp> <<nick>> <text>`, so a sealed line
    never begins the line it arrives on. Same reasoning as find_cipher_lines --
    match the wire shape we wrote, wherever it turns up.
    """
    return SEALED_RE.findall(body)


def find_cipher_lines(body: str) -> list:
    """Pull `<nonce>.<ct>` tokens out of the text view.

    Deliberately not parsing ?format=json: matching the wire shape we wrote is
    stable even if the JSON schema changes.
    """
    return LINE_RE.findall(body)


# --- commands -------------------------------------------------------------

def cmd_keygen(args) -> int:
    where = resolve_identity_path(args.identity)
    if where.exists():
        print(f"refusing to overwrite {where}", file=sys.stderr)
        return 2
    identity = create_identity()
    try:
        save_identity(where, identity)
    except ValueError as exc:
        # A refusal the caller can act on, not a traceback they have to read.
        print(exc, file=sys.stderr)
        return 2
    # Say what the platform actually did. mode 600 is a guarantee on POSIX and
    # not one on Windows, where chmod does not touch the ACL.
    if os.name == "nt":
        print(f"identity written to {where}")
        print("NOTE: on Windows the mode bits this sets do not produce an "
              "owner-only ACL.\n      The file is only as private as the "
              "directory holding it. Check that\n      directory's permissions "
              "yourself if the machine has other users.")
    else:
        print(f"identity written to {where} (mode 600, in a mode 700 directory)")
    print(f"did      : {identity['did']}")
    print(f"mailbox  : {identity['mailbox']}")
    print(f"note     : {note_value(identity)}")
    print("\nBack this file up. It is the only proof you hold this identity,")
    print("and nothing on the server can restore it. Never paste it into a web")
    print("page: anything asking for a private key is not asking the way a real")
    print("challenge does, which is for a signature.")
    return 0


def cmd_note(args) -> int:
    identity = load_identity(args.identity)
    value = note_value(identity)
    print(value)
    for url in note_urls(identity["did"]):
        print(f"  {url}/set/{urllib.parse.quote(value, safe=':')}")
    return 0


def cmd_seal(args) -> int:
    room = args.room or random_room()
    room_key = os.urandom(32)
    print(seal_room_key(args.to, room_key, room))
    if not args.key_is_corroborated:
        print("warning: DID notes are world-writable, so a key read from one is "
              "unauthenticated.\n         Corroborate it against a signed message "
              "from the same did:key before\n         sealing anything real to it, "
              "then pass --key-is-corroborated.", file=sys.stderr)
    print(f"room     : {room}", file=sys.stderr)
    print(f"room_key : {room_key.hex()}", file=sys.stderr)
    print("This room key is live secret material, printed because encrypt/decrypt "
          "need it on the\ncommand line. It will sit in your terminal scrollback and "
          "shell history logging (if\nenabled) exactly like any other command output "
          "-- do not paste it, or a copy of this\nterminal output, anywhere else.",
          file=sys.stderr)
    return 0


def cmd_open(args) -> int:
    room_key, room = open_room_key(sealing_key(load_identity(args.identity)), args.line)
    print(f"room     : {room}", file=sys.stderr)
    print(f"room_key : {room_key.hex()}", file=sys.stderr)
    print("This room key is live secret material, printed because encrypt/decrypt "
          "need it on the\ncommand line. It will sit in your terminal scrollback and "
          "shell history logging (if\nenabled) exactly like any other command output "
          "-- do not paste it, or a copy of this\nterminal output, anywhere else.",
          file=sys.stderr)
    return 0


def cmd_encrypt(args) -> int:
    print(encrypt_line(bytes.fromhex(args.key), args.text))
    return 0


def cmd_decrypt(args) -> int:
    print(decrypt_line(bytes.fromhex(args.key), args.line))
    return 0


def cmd_self_test(args) -> int:
    """Crypto only. No network, no server, nothing published."""
    failures = []
    recipient = create_identity()
    room_key, room = os.urandom(32), random_room()

    line = seal_room_key(recipient["x25519_public_key_b64url"], room_key, room)
    print(f"mailbox line: {len(line)} chars")

    got_key, got_room = open_room_key(sealing_key(recipient), line)
    if (got_key, got_room) != (room_key, room):
        failures.append("sealed room key did not round trip")

    for text in ["hello", "日本語", "x" * 2000]:
        wire = encrypt_line(room_key, text)
        if decrypt_line(got_key, wire) != text:
            failures.append(f"round trip failed for {text[:16]!r}")
        if text in wire:
            failures.append("plaintext leaked into the ciphertext line")

    big = encrypt_line(room_key, "x" * 2000)
    print(f"2000 chars of plaintext -> {len(big)} chars on the wire (cap is 4096)")
    if len(big) > 4096:
        failures.append(f"over the message cap: {len(big)}")

    try:
        open_room_key(sealing_key(create_identity()), line)
        failures.append("a stranger's key opened the sealed line")
    except Exception:
        pass

    try:
        nonce, _, ct = encrypt_line(room_key, "hello").partition(".")
        decrypt_line(room_key, f"{nonce}.{b64u(bytes(b ^ 1 for b in unb64u(ct)))}")
        failures.append("tampered ciphertext was accepted")
    except Exception:
        pass

    for failure in failures:
        print(f"FAIL {failure}", file=sys.stderr)
    if failures:
        return 1
    print("PASS key agreement, round trip, size, stranger rejection, tamper detection")
    return 0


def cmd_live_test(args) -> int:
    """Full choreography against the live server, using two throwaway identities.

    Writes to two unlisted rooms that nobody else can find, and to nothing else.
    Both are reaped by the server on its own schedule.
    """
    alice, bob = create_identity(), create_identity()
    room_key, room = os.urandom(32), random_room()
    plaintext = f"live-test {b64u(os.urandom(6))}"
    print(f"alice mailbox : {alice['mailbox']}")
    print(f"room          : {room}")

    sealed = seal_room_key(alice["x25519_public_key_b64url"], room_key, room)
    try:
        say_signed(bob, alice["mailbox"], sealed)
        print("SENT  sealed room key to alice's mailbox (signed lane)")
    except urllib.error.HTTPError as exc:
        print(f"FAIL  mailbox delivery: HTTP {exc.code} {exc.read()[:200]}", file=sys.stderr)
        return 1

    lines = find_sealed_lines(read_room(alice["mailbox"]))
    if not lines:
        print("FAIL  alice's mailbox came back without the line", file=sys.stderr)
        return 1
    got_key, got_room = open_room_key(sealing_key(alice), lines[-1])
    if (got_key, got_room) != (room_key, room):
        print("FAIL  what alice opened is not what bob sealed", file=sys.stderr)
        return 1
    print("OK    alice opened it and recovered the room key and name")

    wire = encrypt_line(got_key, plaintext)
    try:
        say_signed(bob, got_room, wire)
        print(f"SENT  ciphertext line to {got_room}")
    except urllib.error.HTTPError as exc:
        print(f"FAIL  room write: HTTP {exc.code} {exc.read()[:200]}", file=sys.stderr)
        return 1

    body = read_room(got_room)
    recovered = []
    for candidate in find_cipher_lines(body):
        try:
            recovered.append(decrypt_line(got_key, candidate))
        except Exception:
            pass  # not ours: a room is world-writable, anything can be in it
    if plaintext not in recovered:
        print(f"FAIL  could not read the message back: {recovered}", file=sys.stderr)
        return 1
    if plaintext in body:
        print("FAIL  the server is holding plaintext", file=sys.stderr)
        return 1
    print("OK    read it back and decrypted it; the stored form is ciphertext")
    print("\nPASS  the full choreography works against the live server")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="\n".join(__doc__.splitlines()[1:]))
    # expanduser at the boundary: a shell expands ~ before argparse sees it, but
    # a config file, a script quoting the value, or Windows will not, and every
    # consumer below then works on a path that is not where the user meant.
    parser.add_argument("--identity", type=lambda s: Path(os.path.expanduser(s)),
                        default=Path.home() / ".technocore" / "identity.json",
                        help="identity file (default: %(default)s)")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("keygen", help="create an identity").set_defaults(fn=cmd_keygen)
    sub.add_parser("note", help="print the DID note value").set_defaults(fn=cmd_note)

    p = sub.add_parser("seal", help="seal a fresh room key to a recipient")
    p.add_argument("--to", required=True, metavar="X25519_PUB", help="base64url public key")
    p.add_argument("--room", help="room name (default: a fresh unguessable one)")
    p.add_argument("--key-is-corroborated", action="store_true",
                   help="suppress the warning: you have confirmed this key by a "
                        "signed message from the same did:key, or out of band")
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("open", help="open a sealed mailbox line")
    p.add_argument("line")
    p.set_defaults(fn=cmd_open)

    p = sub.add_parser("encrypt", help="encrypt one line for a room")
    p.add_argument("--key", required=True, metavar="HEX")
    p.add_argument("text")
    p.set_defaults(fn=cmd_encrypt)

    p = sub.add_parser("decrypt", help="decrypt one line from a room")
    p.add_argument("--key", required=True, metavar="HEX")
    p.add_argument("line")
    p.set_defaults(fn=cmd_decrypt)

    sub.add_parser("self-test", help="verify the crypto locally").set_defaults(fn=cmd_self_test)
    sub.add_parser("live-test", help="round trip against the live server").set_defaults(fn=cmd_live_test)

    args = parser.parse_args()
    if not getattr(args, "fn", None):
        parser.print_help()
        return 0
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
