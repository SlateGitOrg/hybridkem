//! Post-handshake transport encryption: one ChaCha20-Poly1305 cipher state per direction.

use super::cipher::{CipherState, HASH_LEN, TAG_LEN};
use super::MAX_MESSAGE_LEN;
use crate::error::{Error, Result};

/// Largest plaintext that fits in one transport message.
pub const MAX_PLAINTEXT_LEN: usize = MAX_MESSAGE_LEN - TAG_LEN;

/// An established session.
///
/// Messages must be decrypted in the order they were encrypted; reordering, replay, loss or
/// tampering all surface as [`Error::Decrypt`] because the nonce is an implicit counter.
#[derive(Debug)]
pub struct TransportState {
    send: CipherState,
    recv: CipherState,
    handshake_hash: [u8; HASH_LEN],
    remote_static: Option<Vec<u8>>,
    skem_to_peer: bool,
    peer_authenticated: bool,
}

impl TransportState {
    pub(crate) fn new(
        send: CipherState,
        recv: CipherState,
        handshake_hash: [u8; HASH_LEN],
        remote_static: Option<Vec<u8>>,
        skem_to_peer: bool,
        peer_authenticated: bool,
    ) -> Self {
        Self {
            send,
            recv,
            handshake_hash,
            remote_static,
            skem_to_peer,
            peer_authenticated,
        }
    }

    /// Encrypt one message (at most [`MAX_PLAINTEXT_LEN`] bytes).
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::MessageTooLarge {
                len: plaintext.len(),
                max: MAX_PLAINTEXT_LEN,
            });
        }
        self.send.encrypt_with_ad(&[], plaintext)
    }

    /// Decrypt the next message from the peer.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() > MAX_MESSAGE_LEN {
            return Err(Error::MessageTooLarge {
                len: ciphertext.len(),
                max: MAX_MESSAGE_LEN,
            });
        }
        let plaintext = self.recv.decrypt_with_ad(&[], ciphertext)?;
        if self.skem_to_peer {
            // The receive key descends from our `skem` to the peer's static key.
            self.peer_authenticated = true;
        }
        Ok(plaintext)
    }

    /// Rotate our sending key (the peer must call [`rekey_incoming`](Self::rekey_incoming)
    /// at the same point in the message stream).
    pub fn rekey_outgoing(&mut self) {
        self.send.rekey();
    }

    /// Rotate the receiving key.
    pub fn rekey_incoming(&mut self) {
        self.recv.rekey();
    }

    /// Unique session identifier (the final handshake hash) for channel binding.
    pub fn handshake_hash(&self) -> &[u8; HASH_LEN] {
        &self.handshake_hash
    }

    /// The peer static key, if the pattern transmitted or pre-shared one.
    ///
    /// It is proven (not merely claimed) only once
    /// [`peer_authenticated`](Self::peer_authenticated) is true.
    pub fn remote_static(&self) -> Option<&[u8]> {
        self.remote_static.as_deref()
    }

    /// True once the peer has proven it holds the secret for
    /// [`remote_static`](Self::remote_static).
    ///
    /// An initiator (`pqNK`, `pqIK`, `pqXX`) is already authenticated-to when the handshake
    /// ends. A `pqIK` or `pqXX` responder becomes so only when the first transport message
    /// from the initiator decrypts; until then every payload it has seen, including
    /// handshake payloads, could have been written by anyone who knows the initiator's public
    /// key. Always false for a `pqNK` responder, whose peer is anonymous.
    pub fn peer_authenticated(&self) -> bool {
        self.peer_authenticated
    }

    /// `(sent, received)` message counts, i.e. the next nonces.
    pub fn counters(&self) -> (u64, u64) {
        (self.send.nonce(), self.recv.nonce())
    }

    #[cfg(test)]
    pub(crate) fn force_send_nonce(&mut self, n: u64) {
        self.send.set_nonce(n);
    }
}
