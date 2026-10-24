# Threat model

> **Educational, not audited.** This document describes what the design *intends* to resist
> and how that is checked. It is not an assurance that the code achieves it. Do not use this
> crate to protect real data.

## What is being protected

1. **Session secrets**: the ML-KEM / hybrid shared secrets and the keys derived from them
   during a handshake, and the transport keys after it.
2. **Long-term secret keys**: ML-KEM seeds (`d || z`), hybrid seeds, X25519 scalars.
3. **Traffic**: confidentiality and integrity of handshake payloads and transport messages,
   and in mutual patterns the identity of the initiator.

## Adversaries considered

| Adversary | Capability | Intended outcome |
|---|---|---|
| Passive network observer, classical | records all traffic | learns sizes and timing of messages only |
| "Harvest now, decrypt later" | records traffic today, gets a quantum computer later (breaks X25519) | hybrid and pure ML-KEM sessions stay confidential as long as ML-KEM holds |
| Cryptanalytic break of ML-KEM | ML-KEM turns out weaker than believed | hybrid sessions stay confidential as long as X25519 holds (this is why the hybrid exists) |
| Active network attacker | modifies, drops, replays, reorders, injects messages; can run its own handshakes | cannot complete a handshake as a party whose static key it lacks; tampering, replay and reordering are detected (`Error::Decrypt`). It **can** deliver a forged pqIK message 1 (or pqXX message 3) claiming any initiator whose public key it knows; `peer_authenticated()` stays false for it (see "Known weaknesses") |
| Chosen-ciphertext attacker against decapsulation | submits many malformed ciphertexts to a party holding a key | learns nothing from return values (implicit rejection returns a pseudorandom key, not an error) |
| Local timing observer | measures how long decapsulation takes, possibly remotely over many queries | should learn nothing about whether a ciphertext was valid or what message it carried |

## Out of scope

- Power, electromagnetic, cache-line or speculative-execution side channels; fault injection.
- Compromise of the host, the OS RNG, or the memory of a running process. Zeroization is
  best-effort: secret types wipe on drop, but the compiler may leave copies on the stack.
- Denial of service (a party can always be made to waste a KEM decapsulation per message).
- Traffic analysis: message lengths are not padded.
- Key distribution: how the initiator learns the responder's static key (IK/NK) or how a
  verifier decides which keys to trust (XX) is the application's job.
- Anything about the classical primitives beyond their documented behaviour (X25519,
  ChaCha20-Poly1305, SHA-2/3, HKDF come from RustCrypto / dalek crates).

## Mechanisms and how each is checked

| Property | Mechanism | Evidence in this repo |
|---|---|---|
| ML-KEM correctness | implemented from FIPS 203 | 243 ACVP vectors (`make check`, `hybridkem kat`); byte-for-byte differential tests vs the `ml-kem` crate (`tests/crosscheck.rs`) |
| Input validation | FIPS 203 modulus check on `ek`, hash check on `dk`, length checks everywhere | ACVP `encapsulationKeyCheck` / `decapsulationKeyCheck` vectors; differential modulus-check test |
| IND-CCA2 behaviour on bad ciphertexts | Fujisaki-Okamoto re-encryption with implicit rejection `J(z || c)` | ACVP "modified ciphertext" vectors; property test: every single-bit flip changes the key |
| No secret-dependent branches in decapsulation | `subtle` comparison and selection; branch-free field arithmetic; reciprocal-based `Compress` | code review (see `docs/ARCHITECTURE.md`); dudect fixed-vs-random tests (`make ct`) with a leaky positive control |
| Hybrid security | combiner hashes both shared secrets plus ciphertext/key material | X-Wing draft-06 vectors and differential test vs the `x-wing` crate; tests showing either half's tampering changes the secret |
| Mutual authentication (IK, XX) | `skem` tokens: only the static-key holder can derive later keys; the proof reaches the `skem` sender when the next message decrypts, reported by `peer_authenticated()` | tests: wrong responder key, unpinned/untrusted initiator, prologue mismatch all fail the handshake; `ik_message1_is_forgeable_from_public_key_but_reported_unauthenticated`, `peer_authenticated_follows_the_skem_rule_in_every_pattern` |
| Integrity, replay and reordering protection | ChaCha20-Poly1305 with counter nonces, transcript hash as AD during the handshake | tests: bit flips at several offsets in every message of every pattern; replayed and reordered records rejected |
| Forward secrecy of transport keys | `ekem` to a fresh ephemeral key in every pattern | by construction (design review); not testable as a unit test |

## Known weaknesses and caveats

- **Handshake payloads read by the responder have no sender authentication.** Classic
  Noise IK authenticates message 1 with the `es`/`ss` Diffie-Hellman tokens; a KEM has no
  equivalent, because every KEM token proves possession of a secret only to the party that
  *encapsulated*, not to the one that decapsulates. pqIK message 1 is `skem, e, s`: writing
  it needs only the initiator's static *public* key. An attacker who knows that key can
  forge message 1 with any payload; a responder that pinned the initiator (`pin_peer`) or
  approves it with a verifier accepts it, and `remote_static()` reports the claimed key.
  The attacker cannot read message 2 or finish the handshake. The same holds for the pqXX
  message-3 payload. Applications must not act on these payloads as coming from the
  claimed peer until `HandshakeState::peer_authenticated()` /
  `TransportState::peer_authenticated()` is true, which for an IK/XX responder happens
  only when the first transport message from the initiator decrypts. A pqNK responder never
  authenticates its peer. Regression test:
  `noise::tests::ik_message1_is_forgeable_from_public_key_but_reported_unauthenticated`.
- **First-message payloads** (IK/NK message 1) are encrypted only under keys from the
  `skem` to the responder's static key: they have no forward secrecy and can be replayed to
  the responder, exactly like 0-RTT data in Noise IK or TLS 1.3. Do not put
  non-idempotent requests there.
- **XX without a verifier** authenticates nobody; it only resists passive attackers.
- **Identity hiding**: in XX an *active* attacker learns the responder's static key (as in
  classic Noise XX); in IK and NK the initiator must already know it.
- **Timing evidence is statistical**: a dudect pass at N samples on one machine is not a
  proof of constant time, and the compiler or a different CPU may introduce leaks this
  harness does not see. Hardware division is avoided in `Compress`, but `u64`
  multiplication is assumed constant-time, which is not true on every 32-bit target.
- **No external review**: the transcript combiner and the handshake token rules are this
  project's own constructions, with no security proof of their own.
