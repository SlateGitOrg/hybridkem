//! Length-prefixed framing and a blocking secure channel over any `Read + Write` stream.
//!
//! Each frame is a 2-byte big-endian length followed by that many bytes, the framing the
//! Noise specification suggests for TCP. Both handshake and transport messages use it.

use super::handshake::HandshakeState;
use super::transport::{TransportState, MAX_PLAINTEXT_LEN};
use super::MAX_MESSAGE_LEN;
use crate::error::{Error, Result};
use crate::kem::Kem;
use rand_core::CryptoRng;
use std::io::{Read, Write};

/// Write one frame.
pub fn write_frame<W: Write>(w: &mut W, data: &[u8]) -> Result<()> {
    if data.len() > MAX_MESSAGE_LEN {
        return Err(Error::MessageTooLarge {
            len: data.len(),
            max: MAX_MESSAGE_LEN,
        });
    }
    w.write_all(&(data.len() as u16).to_be_bytes())?;
    w.write_all(data)?;
    w.flush()?;
    Ok(())
}

/// Read one frame.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let mut buf = vec![0u8; usize::from(u16::from_be_bytes(len))];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Statistics about a completed handshake, for logging and the demo.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HandshakeStats {
    /// Bytes of each handshake message in order (both directions).
    pub message_sizes: Vec<usize>,
    /// Payloads received from the peer during the handshake.
    pub received_payloads: Vec<Vec<u8>>,
}

impl HandshakeStats {
    /// Total handshake bytes on the wire, excluding the 2-byte frame headers.
    pub fn total_bytes(&self) -> usize {
        self.message_sizes.iter().sum()
    }
}

/// Run `handshake` to completion over `stream`, sending `payloads[i]` with our i-th message
/// (missing entries mean an empty payload).
pub fn run_handshake<K: Kem, S: Read + Write, R: CryptoRng + ?Sized>(
    stream: &mut S,
    mut handshake: HandshakeState<K>,
    payloads: &[&[u8]],
    rng: &mut R,
) -> Result<(TransportState, HandshakeStats)> {
    let mut stats = HandshakeStats::default();
    let mut sent = 0;
    while !handshake.is_finished() {
        if handshake.is_my_turn() {
            let payload = payloads.get(sent).copied().unwrap_or(&[]);
            let msg = handshake.write_message(payload, rng)?;
            write_frame(stream, &msg)?;
            stats.message_sizes.push(msg.len());
            sent += 1;
        } else {
            let msg = read_frame(stream)?;
            stats.message_sizes.push(msg.len());
            stats.received_payloads.push(handshake.read_message(&msg)?);
        }
    }
    Ok((handshake.into_transport()?, stats))
}

/// An encrypted, authenticated message channel over a byte stream.
pub struct SecureStream<S> {
    inner: S,
    transport: TransportState,
}

impl<S: Read + Write> SecureStream<S> {
    /// Perform the handshake over `inner` and wrap it.
    pub fn handshake<K: Kem, R: CryptoRng + ?Sized>(
        mut inner: S,
        handshake: HandshakeState<K>,
        payloads: &[&[u8]],
        rng: &mut R,
    ) -> Result<(Self, HandshakeStats)> {
        let (transport, stats) = run_handshake(&mut inner, handshake, payloads, rng)?;
        Ok((Self { inner, transport }, stats))
    }

    /// Encrypt and send one message, splitting it across frames if it is large.
    /// The receiver gets the pieces as separate [`recv`](Self::recv) results.
    pub fn send(&mut self, data: &[u8]) -> Result<()> {
        if data.is_empty() {
            let ct = self.transport.encrypt(&[])?;
            return write_frame(&mut self.inner, &ct);
        }
        for chunk in data.chunks(MAX_PLAINTEXT_LEN) {
            let ct = self.transport.encrypt(chunk)?;
            write_frame(&mut self.inner, &ct)?;
        }
        Ok(())
    }

    /// Receive and decrypt one frame.
    pub fn recv(&mut self) -> Result<Vec<u8>> {
        let frame = read_frame(&mut self.inner)?;
        self.transport.decrypt(&frame)
    }

    /// The session state (handshake hash, peer identity, counters).
    pub fn transport(&self) -> &TransportState {
        &self.transport
    }

    /// Give back the underlying stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}
