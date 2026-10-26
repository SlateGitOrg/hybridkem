//! Handshake engine tests: every pattern with several KEMs, plus the failure modes an
//! active attacker or a misconfigured peer can trigger.

use super::*;
use crate::error::Error;
use crate::hybrid::{X25519MlKem512, XWing};
use crate::kem::{Kem, X25519Kem};
use crate::mlkem::{MlKem1024, MlKem512};
use rand::rngs::StdRng;
use rand::SeedableRng;

struct Parties<K: Kem> {
    initiator: HandshakeState<K>,
    responder: HandshakeState<K>,
    i_static: StaticKeypair<K>,
    r_static: StaticKeypair<K>,
}

fn setup<K: Kem>(pattern: Pattern, rng: &mut StdRng) -> Parties<K> {
    let i_static = StaticKeypair::<K>::generate(rng);
    let r_static = StaticKeypair::<K>::generate(rng);
    let mut ib = Builder::<K>::new(pattern).prologue(b"test v1");
    let mut rb = Builder::<K>::new(pattern)
        .prologue(b"test v1")
        .local_static(r_static.clone());
    if pattern.needs_local_static(Role::Initiator) {
        ib = ib.local_static(i_static.clone());
    }
    if pattern.responder_static_premessage() {
        ib = ib.remote_static(&r_static.public);
    } else {
        ib = ib.pin_peer(&r_static.public);
    }
    if pattern.authenticates_peer(Role::Responder) {
        rb = rb.pin_peer(&i_static.public);
    }
    Parties {
        initiator: ib.build_initiator().unwrap(),
        responder: rb.build_responder().unwrap(),
        i_static,
        r_static,
    }
}

/// Drive both sides to completion, returning the transcript of handshake messages.
fn complete<K: Kem>(p: &mut Parties<K>, rng: &mut StdRng) -> Vec<Vec<u8>> {
    let mut transcript = Vec::new();
    let mut n = 0u8;
    while !p.initiator.is_finished() {
        let payload = [n; 3];
        let (writer, reader) = if p.initiator.is_my_turn() {
            (&mut p.initiator, &mut p.responder)
        } else {
            (&mut p.responder, &mut p.initiator)
        };
        let msg = writer.write_message(&payload, rng).unwrap();
        assert_eq!(reader.read_message(&msg).unwrap(), payload);
        transcript.push(msg);
        n += 1;
    }
    assert!(p.responder.is_finished());
    transcript
}

fn full_round_trip<K: Kem>(pattern: Pattern) {
    let mut rng = StdRng::seed_from_u64(42);
    let mut p = setup::<K>(pattern, &mut rng);
    let transcript = complete(&mut p, &mut rng);
    assert_eq!(transcript.len(), pattern.messages().len());
    assert_eq!(p.initiator.handshake_hash(), p.responder.handshake_hash());
    assert_eq!(
        p.initiator.remote_static(),
        Some(p.r_static.public.as_slice())
    );
    if pattern.authenticates_peer(Role::Responder) {
        assert_eq!(
            p.responder.remote_static(),
            Some(p.i_static.public.as_slice())
        );
    } else {
        assert_eq!(p.responder.remote_static(), None);
    }
    let mut ti = p.initiator.into_transport().unwrap();
    let mut tr = p.responder.into_transport().unwrap();
    assert_eq!(ti.handshake_hash(), tr.handshake_hash());
    for i in 0..5u8 {
        let c = ti.encrypt(&[i; 100]).unwrap();
        assert_eq!(tr.decrypt(&c).unwrap(), vec![i; 100]);
        let c = tr.encrypt(&[i; 7]).unwrap();
        assert_eq!(ti.decrypt(&c).unwrap(), vec![i; 7]);
    }
    assert_eq!(ti.counters(), (5, 5));
}

#[test]
fn all_patterns_with_xwing() {
    for p in Pattern::ALL {
        full_round_trip::<XWing>(p);
    }
}

#[test]
fn all_patterns_with_pure_mlkem_and_other_hybrids() {
    for p in Pattern::ALL {
        full_round_trip::<MlKem512>(p);
        full_round_trip::<MlKem1024>(p);
        full_round_trip::<X25519MlKem512>(p);
        full_round_trip::<X25519Kem>(p);
    }
}

#[test]
fn flipping_any_region_of_any_message_breaks_the_handshake() {
    // Flip one bit at several offsets in each message in turn; the reader must reject it
    // (AEAD failure, or implicit rejection leading to AEAD failure).
    for pattern in Pattern::ALL {
        let mut rng = StdRng::seed_from_u64(7);
        let honest = {
            let mut p = setup::<X25519MlKem512>(pattern, &mut rng);
            complete(&mut p, &mut rng)
        };
        for (target, honest_msg) in honest.iter().enumerate() {
            for offset in [
                0,
                honest_msg.len() / 3,
                honest_msg.len() / 2,
                honest_msg.len() - 1,
            ] {
                let mut rng = StdRng::seed_from_u64(7);
                let mut p = setup::<X25519MlKem512>(pattern, &mut rng);
                let mut failed = false;
                for idx in 0..pattern.messages().len() {
                    let (writer, reader) = if p.initiator.is_my_turn() {
                        (&mut p.initiator, &mut p.responder)
                    } else {
                        (&mut p.responder, &mut p.initiator)
                    };
                    let mut msg = writer.write_message(&[idx as u8; 3], &mut rng).unwrap();
                    if idx == target {
                        msg[offset] ^= 0x01;
                    }
                    if reader.read_message(&msg).is_err() {
                        failed = true;
                        break;
                    }
                }
                // An `e` token carries an unauthenticated public key: flipping it is caught
                // later, when the peer's ekem/payload no longer decrypts. Either way the
                // two sides must never both finish with matching keys.
                if !failed {
                    let mut ti = p.initiator.into_transport().unwrap();
                    let mut tr = p.responder.into_transport().unwrap();
                    let c = ti.encrypt(b"x").unwrap();
                    assert!(
                        tr.decrypt(&c).is_err(),
                        "{pattern} msg {target} offset {offset}"
                    );
                }
            }
        }
    }
}

#[test]
fn ik_initiator_with_wrong_responder_key_fails() {
    let mut rng = StdRng::seed_from_u64(9);
    let real = StaticKeypair::<XWing>::generate(&mut rng);
    let impostor_view = StaticKeypair::<XWing>::generate(&mut rng);
    let client = StaticKeypair::<XWing>::generate(&mut rng);
    let mut i = Builder::<XWing>::new(Pattern::IK)
        .local_static(client)
        .remote_static(&impostor_view.public)
        .build_initiator()
        .unwrap();
    let mut r = Builder::<XWing>::new(Pattern::IK)
        .local_static(real)
        .build_responder()
        .unwrap();
    let m1 = i.write_message(b"", &mut rng).unwrap();
    // The responder hashed a different `<- s` and decapsulates a ciphertext aimed at
    // another key: implicit rejection gives it a different key, so decryption fails.
    assert!(matches!(r.read_message(&m1), Err(Error::Decrypt)));
    // ... and the failed state cannot be reused.
    assert!(matches!(
        r.write_message(b"", &mut rng),
        Err(Error::OutOfOrder(_))
    ));
    assert!(r.into_transport().is_err());
}

#[test]
fn untrusted_peer_is_rejected_in_xx() {
    let mut rng = StdRng::seed_from_u64(10);
    let r_static = StaticKeypair::<MlKem512>::generate(&mut rng);
    let i_static = StaticKeypair::<MlKem512>::generate(&mut rng);
    let mut i = Builder::<MlKem512>::new(Pattern::XX)
        .local_static(i_static)
        .verifier(|_| false)
        .build_initiator()
        .unwrap();
    let mut r = Builder::<MlKem512>::new(Pattern::XX)
        .local_static(r_static)
        .build_responder()
        .unwrap();
    let m1 = i.write_message(b"", &mut rng).unwrap();
    r.read_message(&m1).unwrap();
    let m2 = r.write_message(b"", &mut rng).unwrap();
    assert!(matches!(i.read_message(&m2), Err(Error::UntrustedPeer)));
}

#[test]
fn pinned_remote_static_must_match_in_xx() {
    let mut rng = StdRng::seed_from_u64(11);
    let r_static = StaticKeypair::<MlKem512>::generate(&mut rng);
    let other = StaticKeypair::<MlKem512>::generate(&mut rng);
    let i_static = StaticKeypair::<MlKem512>::generate(&mut rng);
    let mut i = Builder::<MlKem512>::new(Pattern::XX)
        .local_static(i_static)
        .remote_static(&other.public)
        .build_initiator()
        .unwrap();
    let mut r = Builder::<MlKem512>::new(Pattern::XX)
        .local_static(r_static)
        .build_responder()
        .unwrap();
    let m1 = i.write_message(b"", &mut rng).unwrap();
    r.read_message(&m1).unwrap();
    let m2 = r.write_message(b"", &mut rng).unwrap();
    assert!(matches!(i.read_message(&m2), Err(Error::UntrustedPeer)));
}

#[test]
fn prologue_mismatch_fails() {
    let mut rng = StdRng::seed_from_u64(12);
    let r_static = StaticKeypair::<MlKem512>::generate(&mut rng);
    let mut i = Builder::<MlKem512>::new(Pattern::NK)
        .prologue(b"v1")
        .remote_static(&r_static.public)
        .build_initiator()
        .unwrap();
    let mut r = Builder::<MlKem512>::new(Pattern::NK)
        .prologue(b"v2")
        .local_static(r_static)
        .build_responder()
        .unwrap();
    let m1 = i.write_message(b"hi", &mut rng).unwrap();
    assert!(matches!(r.read_message(&m1), Err(Error::Decrypt)));
}

#[test]
fn configuration_errors() {
    let mut rng = StdRng::seed_from_u64(13);
    let kp = StaticKeypair::<MlKem512>::generate(&mut rng);
    assert!(matches!(
        Builder::<MlKem512>::new(Pattern::IK)
            .local_static(kp.clone())
            .build_initiator(),
        Err(Error::MissingKey(_))
    ));
    assert!(matches!(
        Builder::<MlKem512>::new(Pattern::XX).build_responder(),
        Err(Error::MissingKey(_))
    ));
    assert!(matches!(
        Builder::<MlKem512>::new(Pattern::NK)
            .remote_static(&[0; 3])
            .build_initiator(),
        Err(Error::InvalidLength { .. })
    ));
    assert!(matches!(
        Builder::<MlKem512>::new(Pattern::NK)
            .local_static(kp.clone())
            .remote_static(&kp.public)
            .build_responder(),
        Err(Error::InvalidConfig(_))
    ));
    let s = format!("{kp:?}");
    assert!(s.contains("redacted") && s.contains("800 byte"));
    let again = StaticKeypair::<MlKem512>::from_secret(kp.secret.clone());
    assert_eq!(again.public, kp.public);
}

#[test]
fn out_of_turn_and_truncated_messages() {
    let mut rng = StdRng::seed_from_u64(14);
    let mut p = setup::<MlKem512>(Pattern::IK, &mut rng);
    assert_eq!(p.initiator.role(), Role::Initiator);
    assert_eq!(p.responder.pattern(), Pattern::IK);
    assert!(matches!(
        p.responder.write_message(b"", &mut rng),
        Err(Error::OutOfOrder(_))
    ));
    assert!(matches!(
        p.initiator.read_message(b""),
        Err(Error::OutOfOrder(_))
    ));
    let m1 = p.initiator.write_message(b"", &mut rng).unwrap();
    assert!(matches!(
        p.responder.read_message(&m1[..m1.len() - 20]),
        Err(Error::Truncated { .. }) | Err(Error::Decrypt)
    ));

    let mut p = setup::<MlKem512>(Pattern::IK, &mut rng);
    let m1 = p.initiator.write_message(b"", &mut rng).unwrap();
    assert!(matches!(
        p.responder.read_message(&m1[..10]),
        Err(Error::Truncated { .. })
    ));

    let mut p = setup::<MlKem512>(Pattern::IK, &mut rng);
    let huge = vec![0u8; MAX_MESSAGE_LEN + 1];
    assert!(matches!(
        p.responder.read_message(&huge),
        Err(Error::MessageTooLarge { .. })
    ));
    assert!(matches!(
        p.initiator.write_message(&huge, &mut rng),
        Err(Error::MessageTooLarge { .. })
    ));
    assert!(format!("{:?}", p.initiator).contains("HybridNoise_pqIK_ML-KEM-512"));
}

#[test]
fn payload_without_tag_is_truncated() {
    let mut rng = StdRng::seed_from_u64(15);
    let mut p = setup::<X25519Kem>(Pattern::NK, &mut rng);
    let m1 = p.initiator.write_message(b"", &mut rng).unwrap();
    // skem ct (32 bytes, no key yet) + e (32) + tag (16): drop part of the tag.
    assert_eq!(m1.len(), 32 + 32 + 16);
    assert!(matches!(
        p.responder.read_message(&m1[..70]),
        Err(Error::Truncated { .. })
    ));
}

#[test]
fn finished_handshake_rejects_further_messages() {
    let mut rng = StdRng::seed_from_u64(16);
    let mut p = setup::<MlKem512>(Pattern::NK, &mut rng);
    complete(&mut p, &mut rng);
    assert!(matches!(
        p.initiator.write_message(b"", &mut rng),
        Err(Error::OutOfOrder(_))
    ));
    let mut q = setup::<MlKem512>(Pattern::NK, &mut rng);
    assert!(q.initiator.write_message(b"", &mut rng).is_ok());
    assert!(matches!(
        q.initiator.into_transport(),
        Err(Error::OutOfOrder(_))
    ));
}

#[test]
fn transport_ordering_replay_rekey_and_limits() {
    let mut rng = StdRng::seed_from_u64(17);
    let mut p = setup::<XWing>(Pattern::IK, &mut rng);
    complete(&mut p, &mut rng);
    let mut ti = p.initiator.into_transport().unwrap();
    let mut tr = p.responder.into_transport().unwrap();
    assert!(ti.remote_static().is_some());

    let c0 = ti.encrypt(b"zero").unwrap();
    let c1 = ti.encrypt(b"one").unwrap();
    assert!(matches!(tr.decrypt(&c1), Err(Error::Decrypt)), "reordered");
    assert_eq!(tr.decrypt(&c0).unwrap(), b"zero");
    assert!(matches!(tr.decrypt(&c0), Err(Error::Decrypt)), "replayed");
    assert_eq!(tr.decrypt(&c1).unwrap(), b"one");

    ti.rekey_outgoing();
    let c2 = ti.encrypt(b"two").unwrap();
    tr.rekey_incoming();
    assert_eq!(tr.decrypt(&c2).unwrap(), b"two");

    assert!(matches!(
        ti.encrypt(&vec![0; MAX_PLAINTEXT_LEN + 1]),
        Err(Error::MessageTooLarge { .. })
    ));
    assert!(ti.encrypt(&vec![0; MAX_PLAINTEXT_LEN]).is_ok());
    assert!(matches!(
        tr.decrypt(&vec![0; MAX_MESSAGE_LEN + 1]),
        Err(Error::MessageTooLarge { .. })
    ));
    ti.force_send_nonce(u64::MAX);
    assert!(matches!(ti.encrypt(b"x"), Err(Error::NonceExhausted)));
}

#[test]
fn protocol_names_are_distinct_per_kem_and_pattern() {
    assert_eq!(
        protocol_name::<XWing>(Pattern::IK),
        "HybridNoise_pqIK_X-Wing(X25519+ML-KEM-768)_ChaChaPoly_SHA256"
    );
    assert_ne!(
        protocol_name::<XWing>(Pattern::IK),
        protocol_name::<XWing>(Pattern::XX)
    );
    assert_ne!(
        protocol_name::<XWing>(Pattern::IK),
        protocol_name::<MlKem512>(Pattern::IK)
    );
}

#[test]
fn framing_round_trip_and_limits() {
    let mut buf = Vec::new();
    write_frame(&mut buf, b"abc").unwrap();
    write_frame(&mut buf, b"").unwrap();
    assert_eq!(&buf[..2], &[0, 3]);
    let mut cursor = std::io::Cursor::new(buf);
    assert_eq!(read_frame(&mut cursor).unwrap(), b"abc");
    assert_eq!(read_frame(&mut cursor).unwrap(), b"");
    assert!(matches!(read_frame(&mut cursor), Err(Error::Io(_))));
    assert!(matches!(
        write_frame(&mut Vec::new(), &vec![0; MAX_MESSAGE_LEN + 1]),
        Err(Error::MessageTooLarge { .. })
    ));
}

/// Regression: in pqIK no token of message 1 uses the initiator's static
/// *secret*, so anyone who knows the initiator's public key can write a message 1 that a
/// pinned responder accepts. The forger cannot finish the session; `peer_authenticated`
/// must report the payload as unauthenticated until a transport message decrypts.
#[test]
fn ik_message1_is_forgeable_from_public_key_but_reported_unauthenticated() {
    let mut rng = StdRng::seed_from_u64(19);
    let server = StaticKeypair::<XWing>::generate(&mut rng);
    let client = StaticKeypair::<XWing>::generate(&mut rng);
    let attacker = StaticKeypair::<XWing>::generate(&mut rng);
    // The attacker knows only the client's public key.
    let forged_identity = StaticKeypair::<XWing> {
        secret: attacker.secret.clone(),
        public: client.public.clone(),
    };
    let mut forger = Builder::<XWing>::new(Pattern::IK)
        .local_static(forged_identity)
        .remote_static(&server.public)
        .build_initiator()
        .unwrap();
    let mut r = Builder::<XWing>::new(Pattern::IK)
        .local_static(server)
        .pin_peer(&client.public)
        .build_responder()
        .unwrap();

    let m1 = forger
        .write_message(b"transfer 100 to attacker", &mut rng)
        .unwrap();
    // The pin passes and the payload decrypts: message 1 carries no sender authentication.
    assert_eq!(r.read_message(&m1).unwrap(), b"transfer 100 to attacker");
    assert_eq!(r.remote_static(), Some(client.public.as_slice()));
    assert!(
        !r.peer_authenticated(),
        "message-1 payload must not count as authenticated"
    );

    // Message 2 is encapsulated to the real client's key, which the forger cannot decapsulate.
    let m2 = r.write_message(b"", &mut rng).unwrap();
    assert!(matches!(forger.read_message(&m2), Err(Error::Decrypt)));
    assert!(!forger.peer_authenticated());

    // The responder finished its side but still has no proof, and a record the forger
    // fabricates (it lacks the transport key) fails and proves nothing.
    let mut tr = r.into_transport().unwrap();
    assert!(!tr.peer_authenticated());
    assert!(matches!(tr.decrypt(&[0u8; 48]), Err(Error::Decrypt)));
    assert!(!tr.peer_authenticated());
}

#[test]
fn peer_authenticated_follows_the_skem_rule_in_every_pattern() {
    for pattern in Pattern::ALL {
        let mut rng = StdRng::seed_from_u64(20);
        let mut p = setup::<MlKem512>(pattern, &mut rng);
        let mut step = 0;
        while !p.initiator.is_finished() {
            let initiator_writes = p.initiator.is_my_turn();
            let (writer, reader) = if initiator_writes {
                (&mut p.initiator, &mut p.responder)
            } else {
                (&mut p.responder, &mut p.initiator)
            };
            let msg = writer.write_message(b"", &mut rng).unwrap();
            reader.read_message(&msg).unwrap();
            step += 1;
            // The responder never gets proof from a handshake message: no KEM token lets
            // the initiator authenticate itself.
            assert!(!p.responder.peer_authenticated(), "{pattern} step {step}");
            // The initiator gets proof only on the last message (the first one it reads
            // after its own skem to the responder's static key).
            assert_eq!(
                p.initiator.peer_authenticated(),
                p.initiator.is_finished(),
                "{pattern} step {step}"
            );
        }
        let mut ti = p.initiator.into_transport().unwrap();
        let mut tr = p.responder.into_transport().unwrap();
        assert!(ti.peer_authenticated());
        assert!(!tr.peer_authenticated());
        let c = ti.encrypt(b"hi").unwrap();
        tr.decrypt(&c).unwrap();
        // NK's responder never encapsulates to an initiator static key: the peer stays
        // anonymous. IK and XX responders are convinced by the first transport message.
        assert_eq!(
            tr.peer_authenticated(),
            pattern != Pattern::NK,
            "{pattern} responder after first transport message"
        );
    }
}
