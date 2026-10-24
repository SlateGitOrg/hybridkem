//! End-to-end: handshake + transport over a real TCP loopback socket, two threads.

use hybridkem::hybrid::XWing;
use hybridkem::kem::Kem;
use hybridkem::mlkem::MlKem1024;
use hybridkem::noise::{Builder, Pattern, SecureStream, StaticKeypair, MAX_PLAINTEXT_LEN};
use hybridkem::Error;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::net::{TcpListener, TcpStream};
use std::thread;

fn echo_session<K: Kem>(pattern: Pattern, seed: u64) {
    let mut rng = StdRng::seed_from_u64(seed);
    let server_key = StaticKeypair::<K>::generate(&mut rng);
    let client_key = StaticKeypair::<K>::generate(&mut rng);
    let server_pub = server_key.public.clone();
    let client_pub = client_key.public.clone();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let server = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(seed + 1);
        let (sock, _) = listener.accept().unwrap();
        let mut b = Builder::<K>::new(pattern)
            .prologue(b"tcp-test")
            .local_static(server_key);
        if pattern.authenticates_peer(hybridkem::noise::Role::Responder) {
            b = b.pin_peer(&client_pub);
        }
        let (mut chan, stats) = SecureStream::handshake(
            sock,
            b.build_responder().unwrap(),
            &[b"server hello"],
            &mut rng,
        )
        .unwrap();
        assert_eq!(stats.message_sizes.len(), pattern.messages().len());
        // Echo until the client says bye.
        loop {
            let msg = chan.recv().unwrap();
            if msg == b"bye" {
                break;
            }
            chan.send(&msg).unwrap();
        }
        *chan.transport().handshake_hash()
    });

    let sock = TcpStream::connect(addr).unwrap();
    let mut b = Builder::<K>::new(pattern).prologue(b"tcp-test");
    if pattern.needs_local_static(hybridkem::noise::Role::Initiator) {
        b = b.local_static(client_key);
    }
    b = if pattern.responder_static_premessage() {
        b.remote_static(&server_pub)
    } else {
        b.pin_peer(&server_pub)
    };
    let (mut chan, stats) =
        SecureStream::handshake(sock, b.build_initiator().unwrap(), &[], &mut rng).unwrap();
    assert!(stats.received_payloads.contains(&b"server hello".to_vec()));
    assert!(stats.total_bytes() > 2 * K::CIPHERTEXT_LEN);

    for size in [0usize, 1, 1000, MAX_PLAINTEXT_LEN] {
        let data: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        chan.send(&data).unwrap();
        assert_eq!(chan.recv().unwrap(), data);
    }
    chan.send(b"bye").unwrap();
    let client_hash = *chan.transport().handshake_hash();
    assert_eq!(server.join().unwrap(), client_hash);
    assert_eq!(
        chan.transport().remote_static(),
        Some(server_pub.as_slice())
    );
}

#[test]
fn xwing_ik_over_tcp() {
    echo_session::<XWing>(Pattern::IK, 100);
}

#[test]
fn mlkem1024_xx_over_tcp() {
    echo_session::<MlKem1024>(Pattern::XX, 200);
}

#[test]
fn xwing_nk_over_tcp() {
    echo_session::<XWing>(Pattern::NK, 300);
}

#[test]
fn oversized_send_is_split_into_frames() {
    let mut rng = StdRng::seed_from_u64(400);
    let server_key = StaticKeypair::<XWing>::generate(&mut rng);
    let server_pub = server_key.public.clone();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(401);
        let (sock, _) = listener.accept().unwrap();
        let hs = Builder::<XWing>::new(Pattern::NK)
            .local_static(server_key)
            .build_responder()
            .unwrap();
        let (mut chan, _) = SecureStream::handshake(sock, hs, &[], &mut rng).unwrap();
        let a = chan.recv().unwrap();
        let b = chan.recv().unwrap();
        // A frame that arrives after the peer hangs up is an I/O error, not a panic.
        let eof = chan.recv();
        (a.len(), b.len(), matches!(eof, Err(Error::Io(_))))
    });
    let sock = TcpStream::connect(addr).unwrap();
    let hs = Builder::<XWing>::new(Pattern::NK)
        .remote_static(&server_pub)
        .build_initiator()
        .unwrap();
    let (mut chan, _) = SecureStream::handshake(sock, hs, &[], &mut rng).unwrap();
    chan.send(&vec![7u8; MAX_PLAINTEXT_LEN + 10]).unwrap();
    drop(chan.into_inner());
    assert_eq!(server.join().unwrap(), (MAX_PLAINTEXT_LEN, 10, true));
}
