//! KEM-based handshake patterns in the style of PQNoise (Angel, Dowling, Hülsing, Schwabe,
//! Weber; ACM CCS 2022).
//!
//! Classic Noise authenticates with Diffie-Hellman tokens (`ee`, `es`, ...). A KEM is not
//! symmetric like DH, so PQNoise replaces them with two *encapsulation* tokens:
//!
//! * `ekem` — encapsulate to the peer's **ephemeral** key (forward secrecy),
//! * `skem` — encapsulate to the peer's **static** key (authentication: only the holder of
//!   the static secret can decapsulate, so only they can derive the following keys).
//!
//! Authentication is therefore *implicit*: a party proves it holds its static key by being
//! able to read (and write) messages encrypted under keys derived from an `skem` aimed at it.
//!
//! A consequence with no counterpart in DH-based Noise: no token lets a party authenticate
//! *itself* to the receiver of its own message. The proof only reaches the side that sent
//! the `skem`, when the next message decrypts. So the responder of `pqIK` and `pqXX` learns
//! that the initiator really holds its static key only from the first transport message,
//! and handshake payloads it reads before that (pqIK message 1, pqXX message 3) can be
//! written by anyone who knows the initiator's *public* key. Check
//! [`HandshakeState::peer_authenticated`](super::HandshakeState::peer_authenticated) before
//! acting on a payload as if it came from the claimed peer.

/// A handshake token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Token {
    /// Send a fresh ephemeral KEM public key in the clear.
    E,
    /// Send our static KEM public key, encrypted if a key is already established.
    S,
    /// Encapsulate to the peer's ephemeral key; mix the shared secret into the key schedule.
    Ekem,
    /// Encapsulate to the peer's static key; mix the shared secret into the key schedule.
    Skem,
}

/// The supported handshake patterns.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Pattern {
    /// `pqNK`: the initiator knows the responder's static key; only the responder is
    /// authenticated (the TLS-like shape). Two messages.
    NK,
    /// `pqIK`: the initiator knows the responder's static key and sends its own static key
    /// in the first message. Mutual authentication once the handshake (two messages, one
    /// round trip) completes and the responder has decrypted a first transport message;
    /// the message-1 payload has **no sender authentication** (anyone who knows the
    /// initiator's public key can forge it, though not complete the handshake).
    IK,
    /// `pqXX`: neither side knows the other in advance; static keys are exchanged encrypted
    /// and checked against a trust policy. Mutual authentication in four messages; as in
    /// `pqIK`, the responder's proof of the initiator arrives with the first transport
    /// message, so the message-3 payload is not sender-authenticated.
    XX,
}

/// Which side of the handshake a party plays.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Sends the first message.
    Initiator,
    /// Receives the first message.
    Responder,
}

impl Role {
    /// Lower-case name for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Initiator => "initiator",
            Role::Responder => "responder",
        }
    }
}

use Token::{Ekem, Skem, E, S};

impl Pattern {
    /// All patterns.
    pub const ALL: [Pattern; 3] = [Pattern::NK, Pattern::IK, Pattern::XX];

    /// Name as used in the protocol string, e.g. `"pqIK"`.
    pub fn name(self) -> &'static str {
        match self {
            Pattern::NK => "pqNK",
            Pattern::IK => "pqIK",
            Pattern::XX => "pqXX",
        }
    }

    /// Whether the initiator must know the responder's static key before starting
    /// (the `<- s` pre-message).
    pub fn responder_static_premessage(self) -> bool {
        matches!(self, Pattern::NK | Pattern::IK)
    }

    /// Whether the given role needs its own static key pair.
    pub fn needs_local_static(self, role: Role) -> bool {
        match (self, role) {
            (Pattern::NK, Role::Initiator) => false,
            (Pattern::NK, Role::Responder) | (Pattern::IK, _) | (Pattern::XX, _) => true,
        }
    }

    /// Whether the given role ends up authenticating the peer's static key.
    pub fn authenticates_peer(self, role: Role) -> bool {
        !matches!((self, role), (Pattern::NK, Role::Responder))
    }

    /// The token sequence of each message; even indices are sent by the initiator.
    pub fn messages(self) -> &'static [&'static [Token]] {
        match self {
            Pattern::NK => &[&[Skem, E], &[Ekem]],
            Pattern::IK => &[&[Skem, E, S], &[Ekem, Skem]],
            Pattern::XX => &[&[E], &[Ekem, S], &[Skem, S], &[Skem]],
        }
    }

    /// Render the pattern in Noise notation, for documentation and the demo.
    pub fn notation(self) -> String {
        let mut out = String::new();
        if self.responder_static_premessage() {
            out.push_str("  <- s\n  ...\n");
        }
        for (i, msg) in self.messages().iter().enumerate() {
            let arrow = if i % 2 == 0 { "->" } else { "<-" };
            let tokens: Vec<&str> = msg
                .iter()
                .map(|t| match t {
                    E => "e",
                    S => "s",
                    Ekem => "ekem",
                    Skem => "skem",
                })
                .collect();
            out.push_str(&format!("  {arrow} {}\n", tokens.join(", ")));
        }
        out
    }
}

impl core::fmt::Display for Pattern {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.name())
    }
}

impl core::str::FromStr for Pattern {
    type Err = crate::Error;

    fn from_str(s: &str) -> crate::Result<Self> {
        match s.to_ascii_lowercase().trim_start_matches("pq") {
            "nk" => Ok(Pattern::NK),
            "ik" => Ok(Pattern::IK),
            "xx" => Ok(Pattern::XX),
            _ => Err(crate::Error::Parse(format!(
                "unknown pattern {s:?}; expected nk, ik or xx"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_kem_token_has_a_key_to_target() {
        // Walk each pattern and check that ekem/skem only appear once the corresponding
        // remote key is known, and that each side sends `s` at most once.
        for p in Pattern::ALL {
            let mut known = [false, false]; // [initiator knows rs, responder knows rs]
            let mut eph = [false, false]; // [initiator knows re, responder knows re]
            known[0] = p.responder_static_premessage();
            for (i, msg) in p.messages().iter().enumerate() {
                let (me, peer) = if i % 2 == 0 { (0, 1) } else { (1, 0) };
                for t in *msg {
                    match t {
                        E => eph[peer] = true,
                        S => known[peer] = true,
                        Ekem => assert!(eph[me], "{p}: ekem before peer e"),
                        Skem => assert!(known[me], "{p}: skem before peer s"),
                    }
                }
            }
            // Mutual patterns: both sides end up knowing the other's static key.
            if p.authenticates_peer(Role::Responder) {
                assert!(known[1], "{p}");
            }
            assert!(known[0], "{p}");
        }
    }

    #[test]
    fn names_notation_and_parsing() {
        assert_eq!(Pattern::IK.to_string(), "pqIK");
        assert_eq!("ik".parse::<Pattern>().unwrap(), Pattern::IK);
        assert_eq!("pqXX".parse::<Pattern>().unwrap(), Pattern::XX);
        assert_eq!("NK".parse::<Pattern>().unwrap(), Pattern::NK);
        assert!("kk".parse::<Pattern>().is_err());
        assert_eq!(
            Pattern::IK.notation(),
            "  <- s\n  ...\n  -> skem, e, s\n  <- ekem, skem\n"
        );
        assert!(Pattern::XX.notation().starts_with("  -> e\n"));
        assert_eq!(Role::Initiator.as_str(), "initiator");
        assert!(!Pattern::NK.needs_local_static(Role::Initiator));
        assert!(Pattern::XX.needs_local_static(Role::Initiator));
        assert!(!Pattern::NK.authenticates_peer(Role::Responder));
    }
}
