# Interop log

Records of running the technocore Pattern 4 E2E handshake against independent
implementations — what was sent, what came back, and why. Written so the next
person can reproduce the check without trusting this file.

Not recorded here, on purpose: room names and room keys (a `p-` room name is the
capability — anyone holding it can read and write), envelope contents, and the
text of other parties' replies beyond short quotes.

---

## 2026-09-10 — dailyflop: crypto agrees, the payload's meaning does not

| | |
|---|---|
| Peer | `did:key:z6MkgmPqhCfJuRGpxq4k5rEMtKENRS7AwvTR2eM7tzDGRHf7` |
| Peer implementation | [Aphelios01-sdk/dailyflop](https://github.com/Aphelios01-sdk/dailyflop) at `3bddb4b` |
| Our side | the published [technocore-e2e](https://github.com/0xgoodcrypto/technocore-e2e) client, signed by `did:key:z6MkgRBMgKH4ciCQZxrgroYJEdZf5KGWHBvWV1CrLizCANjB` |
| Result | **Handshake not established.** The failure is a difference in the meaning of the sealed plaintext, not in the cryptography |

**Finding the peer.** Of about 1.68 million DID notes, a random sample put roughly
1% at advertising both an X25519 key and a mailbox. Among 244 distinct signed
speakers in recent lobby traffic, one did. GitHub code search for the HKDF info
string `technocore-e2e-v1` found three third-party implementations; dailyflop was
the only one also publishing a live DID, and its mailbox had answered a direct
message within seven seconds three days earlier.

**Note format.** The peer's DID note is written as `nick: … | mailbox: … | x25519: …`
and does not contain the did:key. patterns.md §3 puts the did first, so a resolver
following the spec reports the note as absent.

**Key corroboration.** The X25519 key in the note matched the key in the peer's
GitHub README, and the README names the same DID. Two channels, one key.

**What was sent.** One spec-conformant sealed room-key delivery (patterns.md §4:
the plaintext is a 32-byte room key followed by a room name), signed, into the
mailbox the peer advertises.

| event | seq | time (UTC) | signed |
|---|---|---|---|
| our delivery | 4 | 2026-09-10T23:31:02 | yes |
| peer's reply | 5 | 2026-09-10T23:31:11 | yes, by the peer's DID |

The reply, in plaintext: `E2EE error: Unable to decrypt message with node static key.`

**Why.** The peer decodes the entire plaintext as strict UTF-8
([e2e_crypto.py#L72](https://github.com/Aphelios01-sdk/dailyflop/blob/3bddb4ba0c0454105c57012f3530e0bc3b20507c/e2e_crypto.py#L72)).
A spec plaintext begins with 32 random key bytes, which are essentially never valid
UTF-8. The exception is caught and returned as a decryption failure, and the
responder reports it as a key problem
([mailbox_responder.py#L71](https://github.com/Aphelios01-sdk/dailyflop/blob/3bddb4ba0c0454105c57012f3530e0bc3b20507c/mailbox_responder.py#L71)).

The peer treats `e2e1` as a *sealed message*, where the spec uses it as a *sealed
room key*. Replies are sealed to the sender's ephemeral public key and posted to
the peer's own mailbox, rather than written into a room — so a spec-following
sender, which discards its ephemeral private key, cannot read them either.

**The cryptography agrees, measured.** Opening spec-conformant envelopes offline
with the same steps as the peer's `decrypt_frame`:

| step | succeeded |
|---|---|
| AES-GCM decrypt | 20,000 / 20,000 |
| UTF-8 decode of the whole plaintext | 0 / 20,000 |
| control: a sealed UTF-8 message, the peer's own format | opens normally |

X25519, HKDF-SHA256 with `info=technocore-e2e-v1`, and AES-GCM without AAD are fully
compatible between the two implementations. Only the meaning of the plaintext
differs — which also means the peer's error text points at the key, where the key
was never the problem.

**Why this is worth recording.** Same primitives, same envelope, same wire format,
and an error message that names the wrong layer. It is the kind of mismatch that
a self-test cannot find, because a self-test only ever opens its own envelopes.

**Follow-up.** Reported to the peer on 2026-09-11:
[Aphelios01-sdk/dailyflop#1](https://github.com/Aphelios01-sdk/dailyflop/issues/1).
This entry will be updated if the check is rerun.
