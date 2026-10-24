//! `demo` and `handshake`: an offline end-to-end walk through every layer.

use super::keys::fingerprint;
use super::reports::kat;
use hybridkem::hybrid::{HybridDecapsulationKey, TranscriptCombiner, XWingCombiner};
use hybridkem::kem::{Algorithm, Kem};
use hybridkem::mlkem::{DecapsulationKey, MlKem1024, MlKem512, MlKem768, ParameterSet};
use hybridkem::noise::{protocol_name, Builder, Pattern, Role, SecureStream, StaticKeypair};
use hybridkem::{with_kem, Error, Result};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fmt::Write as _;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::thread;

fn short(bytes: &[u8]) -> String {
    format!("{}..", hex::encode(&bytes[..8.min(bytes.len())]))
}

fn mlkem_section<P: ParameterSet>(rng: &mut StdRng, out: &mut String) -> Result<()> {
    let dk = DecapsulationKey::<P>::generate(rng);
    let (ct, k_sender) = dk.encapsulation_key().encapsulate(rng);
    let k_receiver = dk.decapsulate(ct.as_bytes())?;
    let mut forged = ct.clone().into_bytes();
    forged[0] ^= 1;
    let k_forged = dk.decapsulate(&forged)?;
    let _ = writeln!(
        out,
        "  {:<11} ek {:>4} B  dk {:>4} B  ct {:>4} B  K {}  agree={}  forged-ct K {} (implicit rejection)",
        P::NAME,
        P::EK_LEN,
        P::DK_LEN,
        P::CT_LEN,
        short(k_sender.as_bytes()),
        k_sender == k_receiver,
        short(k_forged.as_bytes()),
    );
    Ok(())
}

fn hybrid_section(rng: &mut StdRng, out: &mut String) -> Result<()> {
    let mut seed = [0u8; 32];
    let mut eseed = [0u8; 64];
    rng.fill_bytes(&mut seed);
    rng.fill_bytes(&mut eseed);
    let xwing = HybridDecapsulationKey::<MlKem768, XWingCombiner>::from_seed(&seed);
    let transcript = HybridDecapsulationKey::<MlKem768, TranscriptCombiner>::from_seed(&seed);
    let (ct_x, ss_x) = xwing
        .encapsulation_key()
        .encapsulate_deterministic(&eseed)?;
    let (ct_t, ss_t) = transcript
        .encapsulation_key()
        .encapsulate_deterministic(&eseed)?;
    let _ = writeln!(
        out,
        "  same 32-byte seed and encapsulation randomness, two combiners over X25519 + ML-KEM-768:"
    );
    let _ = writeln!(
        out,
        "    X-Wing      pk {} B  ct {} B  ss {}  decaps agrees={}",
        xwing.encapsulation_key().as_bytes().len(),
        ct_x.len(),
        short(ss_x.as_bytes()),
        xwing.decapsulate(&ct_x)? == ss_x
    );
    let _ = writeln!(
        out,
        "    transcript  pk {} B  ct {} B  ss {}  decaps agrees={}",
        transcript.encapsulation_key().as_bytes().len(),
        ct_t.len(),
        short(ss_t.as_bytes()),
        transcript.decapsulate(&ct_t)? == ss_t
    );
    let _ = writeln!(
        out,
        "    identical ciphertexts={}, different secrets={} (combiners are domain-separated)",
        ct_x == ct_t,
        ss_x != ss_t
    );
    Ok(())
}

/// Run a handshake between two threads over TCP loopback and exchange a few messages.
pub fn tcp_session<K: Kem>(pattern: Pattern, seed: u64, out: &mut String) -> Result<()> {
    let mut rng = StdRng::seed_from_u64(seed);
    let server_key = StaticKeypair::<K>::generate(&mut rng);
    let client_key = StaticKeypair::<K>::generate(&mut rng);
    let server_pub = server_key.public.clone();
    let client_pub = client_key.public.clone();
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    let server = thread::spawn(move || -> Result<Vec<String>> {
        let mut rng = StdRng::seed_from_u64(seed.wrapping_add(1));
        let (sock, _) = listener.accept()?;
        let mut b = Builder::<K>::new(pattern)
            .prologue(b"hybridkem demo v1")
            .local_static(server_key);
        if pattern.authenticates_peer(Role::Responder) {
            b = b.pin_peer(&client_pub);
        }
        let (mut chan, _) =
            SecureStream::handshake(sock, b.build_responder()?, &[b"server: welcome"], &mut rng)?;
        let mut log = Vec::new();
        for _ in 0..2 {
            let msg = chan.recv()?;
            log.push(String::from_utf8_lossy(&msg).into_owned());
            let reply = format!("server echo: {}", String::from_utf8_lossy(&msg));
            chan.send(reply.as_bytes())?;
        }
        Ok(log)
    });

    let sock = TcpStream::connect(addr)?;
    let mut b = Builder::<K>::new(pattern).prologue(b"hybridkem demo v1");
    if pattern.needs_local_static(Role::Initiator) {
        b = b.local_static(client_key);
    }
    b = if pattern.responder_static_premessage() {
        b.remote_static(&server_pub)
    } else {
        b.pin_peer(&server_pub)
    };
    let (mut chan, stats) = SecureStream::handshake(sock, b.build_initiator()?, &[], &mut rng)?;
    let _ = writeln!(out, "  protocol        {}", protocol_name::<K>(pattern));
    let _ = writeln!(out, "  pattern\n{}", pattern.notation().trim_end());
    let _ = writeln!(
        out,
        "  message sizes   {:?} bytes (total {} B over 127.0.0.1)",
        stats.message_sizes,
        stats.total_bytes()
    );
    let _ = writeln!(
        out,
        "  handshake hash  {}",
        short(chan.transport().handshake_hash())
    );
    let _ = writeln!(
        out,
        "  server static   fingerprint {}",
        fingerprint(&server_pub)
    );
    for p in &stats.received_payloads {
        if !p.is_empty() {
            let _ = writeln!(out, "  payload rcvd    {:?}", String::from_utf8_lossy(p));
        }
    }
    for msg in ["hello over a hybrid channel", "second message"] {
        chan.send(msg.as_bytes())?;
        let reply = chan.recv()?;
        let _ = writeln!(
            out,
            "  client -> {msg:?}  <- {:?}",
            String::from_utf8_lossy(&reply)
        );
    }
    let server_log = server
        .join()
        .map_err(|_| Error::Parse("server thread panicked".into()))??;
    let _ = writeln!(out, "  server saw      {server_log:?}");
    Ok(())
}

fn attack_section(rng: &mut StdRng, out: &mut String) -> Result<()> {
    type K = hybridkem::hybrid::XWing;
    let server = StaticKeypair::<K>::generate(rng);
    let client = StaticKeypair::<K>::generate(rng);
    let impostor = StaticKeypair::<K>::generate(rng);
    let initiator = |remote: &[u8]| {
        Builder::<K>::new(Pattern::IK)
            .local_static(client.clone())
            .remote_static(remote)
            .build_initiator()
    };
    let responder = || {
        Builder::<K>::new(Pattern::IK)
            .local_static(server.clone())
            .pin_peer(&client.public)
            .build_responder()
    };
    let verdict = |r: Result<Vec<u8>>| match r {
        Ok(_) => "ACCEPTED (unexpected)".to_string(),
        Err(e) => format!("rejected: {e}"),
    };

    // 1. A man-in-the-middle flips one bit of the first handshake message.
    let mut i = initiator(&server.public)?;
    let mut r = responder()?;
    let mut m1 = i.write_message(b"", rng)?;
    let mid = m1.len() / 2;
    m1[mid] ^= 0x01;
    let _ = writeln!(
        out,
        "  bit flip in message 1          -> {}",
        verdict(r.read_message(&m1))
    );

    // 2. The client was given the wrong server key (an impostor's): the real server
    //    cannot decapsulate the skem token aimed at the impostor.
    let mut i = initiator(&impostor.public)?;
    let mut r = responder()?;
    let m1 = i.write_message(b"", rng)?;
    let _ = writeln!(
        out,
        "  client pinned wrong server key -> {}",
        verdict(r.read_message(&m1))
    );

    // 3. An unknown client (not pinned by the server) connects.
    let stranger = StaticKeypair::<K>::generate(rng);
    let mut i = Builder::<K>::new(Pattern::IK)
        .local_static(stranger)
        .remote_static(&server.public)
        .build_initiator()?;
    let mut r = responder()?;
    let m1 = i.write_message(b"", rng)?;
    let _ = writeln!(
        out,
        "  unpinned client static key     -> {}",
        verdict(r.read_message(&m1))
    );

    // 4. Replay of a transport record after an honest handshake.
    let mut i = initiator(&server.public)?;
    let mut r = responder()?;
    let m1 = i.write_message(b"", rng)?;
    r.read_message(&m1)?;
    let m2 = r.write_message(b"", rng)?;
    i.read_message(&m2)?;
    let (mut ti, mut tr) = (i.into_transport()?, r.into_transport()?);
    let record = ti.encrypt(b"transfer 100 coins")?;
    let first = tr.decrypt(&record).map(|_| ());
    let _ = writeln!(
        out,
        "  honest transport record        -> {}",
        if first.is_ok() {
            "accepted"
        } else {
            "rejected"
        }
    );
    let _ = writeln!(
        out,
        "  replayed transport record      -> {}",
        verdict(tr.decrypt(&record))
    );
    Ok(())
}

/// The full offline demo.
pub fn demo(vectors: &Path, seed: u64) -> Result<String> {
    let mut out = String::new();
    let mut rng = StdRng::seed_from_u64(seed);
    let _ = writeln!(
        out,
        "hybridkem demo  (educational implementation, NOT audited; do not protect real data)"
    );
    let _ = writeln!(
        out,
        "deterministic RNG seed {seed} so this output is reproducible\n"
    );

    let _ = writeln!(
        out,
        "[1/5] Known-answer tests from pinned, checksummed vector files"
    );
    let (kat_text, kat_ok) = kat(vectors)?;
    for line in kat_text.lines() {
        let _ = writeln!(out, "  {line}");
    }
    if !kat_ok {
        return Err(Error::Parse("known-answer tests failed".into()));
    }

    let _ = writeln!(out, "\n[2/5] ML-KEM (FIPS 203) at every parameter set");
    mlkem_section::<MlKem512>(&mut rng, &mut out)?;
    mlkem_section::<MlKem768>(&mut rng, &mut out)?;
    mlkem_section::<MlKem1024>(&mut rng, &mut out)?;

    let _ = writeln!(out, "\n[3/5] Hybrid X25519 + ML-KEM combiners");
    hybrid_section(&mut rng, &mut out)?;

    let _ = writeln!(out, "\n[4/5] Authenticated pqIK handshake over TCP loopback, X-Wing KEM, ChaCha20-Poly1305 transport");
    tcp_session::<hybridkem::hybrid::XWing>(Pattern::IK, seed, &mut out)?;

    let _ = writeln!(
        out,
        "\n[5/5] Active-attacker simulations (in memory, X-Wing pqIK)"
    );
    attack_section(&mut rng, &mut out)?;

    let _ = writeln!(
        out,
        "\nall sizes per algorithm (public key / ciphertext bytes):"
    );
    for alg in Algorithm::ALL {
        let (pk, ct) = alg.sizes();
        let _ = writeln!(
            out,
            "  {:<34} {:>5} / {:>5}  {}",
            alg.name(),
            pk,
            ct,
            if alg.is_post_quantum() {
                "post-quantum"
            } else {
                "classical only"
            }
        );
    }
    Ok(out)
}

/// `handshake` command: one TCP session with a chosen KEM and pattern.
pub fn handshake(alg: Algorithm, pattern: Pattern, seed: u64) -> Result<String> {
    let mut out = String::new();
    with_kem!(alg, K => tcp_session::<K>(pattern, seed, &mut out))?;
    Ok(out)
}
