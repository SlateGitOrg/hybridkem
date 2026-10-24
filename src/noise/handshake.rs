//! The handshake state machine: interprets a [`Pattern`]'s tokens for either [`Role`].

use super::cipher::{SymmetricState, HASH_LEN, TAG_LEN};
use super::pattern::{Pattern, Role, Token};
use super::transport::TransportState;
use super::MAX_MESSAGE_LEN;
use crate::error::{Error, Result};
use crate::kem::Kem;
use rand_core::CryptoRng;
use std::sync::Arc;

/// A static (long-term) KEM key pair.
pub struct StaticKeypair<K: Kem> {
    /// Secret key.
    pub secret: K::SecretKey,
    /// Encoded public key.
    pub public: Vec<u8>,
}

impl<K: Kem> Clone for StaticKeypair<K> {
    fn clone(&self) -> Self {
        Self {
            secret: self.secret.clone(),
            public: self.public.clone(),
        }
    }
}

impl<K: Kem> core::fmt::Debug for StaticKeypair<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "StaticKeypair<{}>(<redacted>, {} byte public key)",
            K::name(),
            self.public.len()
        )
    }
}

impl<K: Kem> StaticKeypair<K> {
    /// Generate a fresh key pair.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let (secret, public) = K::generate(rng);
        Self { secret, public }
    }

    /// Wrap an existing secret key.
    pub fn from_secret(secret: K::SecretKey) -> Self {
        let public = K::public_key(&secret);
        Self { secret, public }
    }
}

/// Decides whether a peer's static public key is acceptable (e.g. a pinned-key allowlist).
pub type PeerVerifier = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// Configures and creates a [`HandshakeState`].
pub struct Builder<K: Kem> {
    pattern: Pattern,
    prologue: Vec<u8>,
    local_static: Option<StaticKeypair<K>>,
    remote_static: Option<Vec<u8>>,
    verifier: Option<PeerVerifier>,
}

impl<K: Kem> Builder<K> {
    /// Start configuring a handshake for `pattern`.
    pub fn new(pattern: Pattern) -> Self {
        Self {
            pattern,
            prologue: Vec::new(),
            local_static: None,
            remote_static: None,
            verifier: None,
        }
    }

    /// Data both sides must agree on (e.g. a protocol version); hashed into the transcript.
    pub fn prologue(mut self, prologue: &[u8]) -> Self {
        self.prologue = prologue.to_vec();
        self
    }

    /// Our long-term key pair.
    pub fn local_static(mut self, keypair: StaticKeypair<K>) -> Self {
        self.local_static = Some(keypair);
        self
    }

    /// The peer's public key, known in advance. Required for IK/NK initiators (it is the
    /// `<- s` pre-message); in every other position it pins the key the peer must present.
    pub fn remote_static(mut self, public_key: &[u8]) -> Self {
        self.remote_static = Some(public_key.to_vec());
        self
    }

    /// Policy for static keys received *during* the handshake (XX both sides, IK responder).
    /// Without a verifier every well-formed key is accepted, which provides confidentiality
    /// against passive attackers but no authentication — set one in real deployments.
    pub fn verifier(mut self, verifier: impl Fn(&[u8]) -> bool + Send + Sync + 'static) -> Self {
        self.verifier = Some(Arc::new(verifier));
        self
    }

    /// Accept exactly one peer static key.
    pub fn pin_peer(self, public_key: &[u8]) -> Self {
        let pinned = public_key.to_vec();
        self.verifier(move |pk| pk == pinned.as_slice())
    }

    /// Build the initiator side.
    pub fn build_initiator(self) -> Result<HandshakeState<K>> {
        HandshakeState::new(self, Role::Initiator)
    }

    /// Build the responder side.
    pub fn build_responder(self) -> Result<HandshakeState<K>> {
        HandshakeState::new(self, Role::Responder)
    }
}

/// Noise protocol name for a pattern/KEM pair. The `HybridNoise_` prefix marks that this is
/// Noise-*style* (PQNoise-inspired KEM tokens), not a registered Noise protocol.
pub fn protocol_name<K: Kem>(pattern: Pattern) -> String {
    format!(
        "HybridNoise_{}_{}_ChaChaPoly_SHA256",
        pattern.name(),
        K::name()
    )
}

/// One side of an in-progress handshake.
pub struct HandshakeState<K: Kem> {
    pattern: Pattern,
    role: Role,
    symmetric: SymmetricState,
    s: Option<StaticKeypair<K>>,
    e: Option<StaticKeypair<K>>,
    rs: Option<Vec<u8>>,
    re: Option<Vec<u8>>,
    expected_rs: Option<Vec<u8>>,
    verifier: Option<PeerVerifier>,
    message_index: usize,
    failed: bool,
}

impl<K: Kem> core::fmt::Debug for HandshakeState<K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HandshakeState")
            .field("protocol", &protocol_name::<K>(self.pattern))
            .field("role", &self.role)
            .field("message_index", &self.message_index)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl<K: Kem> HandshakeState<K> {
    fn new(b: Builder<K>, role: Role) -> Result<Self> {
        let pattern = b.pattern;
        if pattern.needs_local_static(role) && b.local_static.is_none() {
            return Err(Error::MissingKey("this pattern needs our static key pair"));
        }
        if pattern.responder_static_premessage()
            && role == Role::Initiator
            && b.remote_static.is_none()
        {
            return Err(Error::MissingKey(
                "the initiator must know the responder's static key",
            ));
        }
        if let Some(rs) = &b.remote_static {
            crate::error::check_len("remote static key", rs, K::PUBLIC_KEY_LEN)?;
        }
        // For an IK/NK initiator the configured remote key is the `<- s` pre-message; in
        // every other case it is a pin that the key received in-band must match.
        let premessage = pattern.responder_static_premessage();
        let (rs, expected_rs) = if premessage && role == Role::Initiator {
            (b.remote_static, None)
        } else {
            (None, b.remote_static)
        };
        if expected_rs.is_some() && !pattern.authenticates_peer(role) {
            return Err(Error::InvalidConfig(
                "this pattern never transmits the peer's static key",
            ));
        }
        let mut symmetric = SymmetricState::new(&protocol_name::<K>(pattern));
        symmetric.mix_hash(&b.prologue);
        // Pre-message `<- s`: both sides hash the responder's static public key.
        if premessage {
            let responder_pk = match role {
                Role::Initiator => rs.as_deref(),
                Role::Responder => b.local_static.as_ref().map(|s| s.public.as_slice()),
            };
            symmetric.mix_hash(responder_pk.expect("presence checked above"));
        }
        Ok(Self {
            pattern,
            role,
            symmetric,
            s: b.local_static,
            e: None,
            rs,
            re: None,
            expected_rs,
            verifier: b.verifier,
            message_index: 0,
            failed: false,
        })
    }

    /// Our role.
    pub fn role(&self) -> Role {
        self.role
    }

    /// The pattern being executed.
    pub fn pattern(&self) -> Pattern {
        self.pattern
    }

    /// True once every handshake message has been sent or received.
    pub fn is_finished(&self) -> bool {
        self.message_index == self.pattern.messages().len()
    }

    /// True when the next message is ours to write.
    pub fn is_my_turn(&self) -> bool {
        let initiator_turn = self.message_index % 2 == 0;
        !self.is_finished() && (initiator_turn == (self.role == Role::Initiator))
    }

    /// The transcript hash so far; after the handshake it is a unique session identifier
    /// suitable for channel binding.
    pub fn handshake_hash(&self) -> [u8; HASH_LEN] {
        self.symmetric.handshake_hash()
    }

    /// The peer's static key, once known.
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.rs.as_deref()
    }

    fn check_usable(&self, writing: bool) -> Result<()> {
        if self.failed {
            return Err(Error::OutOfOrder("handshake already failed"));
        }
        if self.is_finished() {
            return Err(Error::OutOfOrder("handshake already finished"));
        }
        if self.is_my_turn() != writing {
            return Err(Error::OutOfOrder(if writing {
                "it is the peer's turn to send"
            } else {
                "it is our turn to send"
            }));
        }
        Ok(())
    }

    /// Produce the next handshake message carrying `payload` (encrypted when a key exists).
    pub fn write_message<R: CryptoRng + ?Sized>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        self.check_usable(true)?;
        let result = self.write_inner(payload, rng);
        self.finish_step(result, "wrote")
    }

    /// Consume the peer's next handshake message, returning its decrypted payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        self.check_usable(false)?;
        if message.len() > MAX_MESSAGE_LEN {
            self.failed = true;
            return Err(Error::MessageTooLarge {
                len: message.len(),
                max: MAX_MESSAGE_LEN,
            });
        }
        let result = self.read_inner(message);
        self.finish_step(result, "read")
    }

    fn finish_step<T: AsRef<[u8]>>(&mut self, result: Result<T>, verb: &str) -> Result<T> {
        match &result {
            Ok(bytes) => {
                log::debug!(
                    "{} {verb} handshake message {} ({} bytes)",
                    self.role.as_str(),
                    self.message_index + 1,
                    bytes.as_ref().len()
                );
                self.message_index += 1;
            }
            Err(e) => {
                log::warn!(
                    "{} handshake failed at message {}: {e}",
                    self.role.as_str(),
                    self.message_index + 1
                );
                // A failed handshake must not be resumed: its transcript is now undefined.
                self.failed = true;
            }
        }
        result
    }

    fn write_inner<R: CryptoRng + ?Sized>(
        &mut self,
        payload: &[u8],
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for &token in self.pattern.messages()[self.message_index] {
            match token {
                Token::E => {
                    let e = StaticKeypair::<K>::generate(rng);
                    self.symmetric.mix_hash(&e.public);
                    out.extend_from_slice(&e.public);
                    self.e = Some(e);
                }
                Token::S => {
                    let s = self.s.as_ref().ok_or(Error::MissingKey("local static"))?;
                    let ct = self.symmetric.encrypt_and_hash(&s.public)?;
                    out.extend_from_slice(&ct);
                }
                Token::Ekem | Token::Skem => {
                    let target = if token == Token::Ekem {
                        self.re
                            .as_deref()
                            .ok_or(Error::MissingKey("remote ephemeral"))?
                    } else {
                        self.rs
                            .as_deref()
                            .ok_or(Error::MissingKey("remote static"))?
                    };
                    let (kem_ct, ss) = K::encapsulate(target, rng)?;
                    let ct = self.symmetric.encrypt_and_hash(&kem_ct)?;
                    out.extend_from_slice(&ct);
                    self.symmetric.mix_key(ss.as_bytes());
                }
            }
        }
        out.extend_from_slice(&self.symmetric.encrypt_and_hash(payload)?);
        if out.len() > MAX_MESSAGE_LEN {
            return Err(Error::MessageTooLarge {
                len: out.len(),
                max: MAX_MESSAGE_LEN,
            });
        }
        Ok(out)
    }

    fn read_inner(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        let mut rest = message;
        let mut take = |n: usize| -> Result<&[u8]> {
            if rest.len() < n {
                return Err(Error::Truncated {
                    needed: n - rest.len(),
                });
            }
            let (head, tail) = rest.split_at(n);
            rest = tail;
            Ok(head)
        };
        for &token in self.pattern.messages()[self.message_index] {
            match token {
                Token::E => {
                    let re = take(K::PUBLIC_KEY_LEN)?.to_vec();
                    self.symmetric.mix_hash(&re);
                    self.re = Some(re);
                }
                Token::S => {
                    let n = self.symmetric.encrypted_len(K::PUBLIC_KEY_LEN);
                    let rs = self.symmetric.decrypt_and_hash(take(n)?)?;
                    if self
                        .expected_rs
                        .as_deref()
                        .is_some_and(|want| want != rs.as_slice())
                    {
                        return Err(Error::UntrustedPeer);
                    }
                    if let Some(verify) = &self.verifier {
                        if !verify(&rs) {
                            return Err(Error::UntrustedPeer);
                        }
                    }
                    self.rs = Some(rs);
                }
                Token::Ekem | Token::Skem => {
                    let n = self.symmetric.encrypted_len(K::CIPHERTEXT_LEN);
                    let kem_ct = self.symmetric.decrypt_and_hash(take(n)?)?;
                    let own = if token == Token::Ekem {
                        &self.e
                    } else {
                        &self.s
                    };
                    let own = own
                        .as_ref()
                        .ok_or(Error::MissingKey("own key for kem token"))?;
                    let ss = K::decapsulate(&own.secret, &kem_ct)?;
                    self.symmetric.mix_key(ss.as_bytes());
                }
            }
        }
        // Whatever remains is the payload; with a key it must at least hold the tag.
        let payload_ct = rest;
        if self.symmetric.encrypted_len(0) > payload_ct.len() {
            return Err(Error::Truncated {
                needed: TAG_LEN - payload_ct.len(),
            });
        }
        self.symmetric.decrypt_and_hash(payload_ct)
    }

    /// Finish the handshake and derive the transport keys (Noise `Split`).
    pub fn into_transport(self) -> Result<TransportState> {
        if self.failed || !self.is_finished() {
            return Err(Error::OutOfOrder("handshake is not complete"));
        }
        let (c1, c2) = self.symmetric.split();
        let (send, recv) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };
        Ok(TransportState::new(
            send,
            recv,
            self.symmetric.handshake_hash(),
            self.rs,
        ))
    }
}
