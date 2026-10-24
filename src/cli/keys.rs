//! `keygen`, `encaps` and `decaps`: file-based KEM operations with hex-encoded files.

use hybridkem::kem::Algorithm;
use hybridkem::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

/// Read a hex file (whitespace tolerated).
pub fn read_hex(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let text = Zeroizing::new(fs::read_to_string(path)?);
    let compact: Zeroizing<String> = Zeroizing::new(text.split_whitespace().collect());
    hex::decode(compact.as_str())
        .map(Zeroizing::new)
        .map_err(|e| Error::Parse(format!("{}: {e}", path.display())))
}

/// Write bytes as a single line of hex.
pub fn write_hex(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut text = Zeroizing::new(hex::encode(bytes));
    text.push('\n');
    fs::write(path, text.as_bytes())?;
    Ok(())
}

/// Short public fingerprint for display: first 8 bytes of SHA-256, hex.
pub fn fingerprint(bytes: &[u8]) -> String {
    hex::encode(&Sha256::digest(bytes)[..8])
}

fn with_ext(prefix: &Path, ext: &str) -> PathBuf {
    let mut p = prefix.as_os_str().to_owned();
    p.push(ext);
    PathBuf::from(p)
}

/// Generate a key pair and write `<prefix>.sk` / `<prefix>.pk`.
pub fn keygen(alg: Algorithm, prefix: &Path) -> Result<String> {
    let mut rng = rand::rng();
    let (sk, pk) = alg.generate(&mut rng);
    let sk_path = with_ext(prefix, ".sk");
    let pk_path = with_ext(prefix, ".pk");
    write_hex(&sk_path, &sk)?;
    write_hex(&pk_path, &pk)?;
    log::info!("wrote {} and {}", sk_path.display(), pk_path.display());
    Ok(format!(
        "algorithm   {}\nsecret key  {} ({} bytes, seed form)\npublic key  {} ({} bytes, fingerprint {})\n",
        alg.name(),
        sk_path.display(),
        sk.len(),
        pk_path.display(),
        pk.len(),
        fingerprint(&pk)
    ))
}

/// Encapsulate to the key in `pk_path`, writing the ciphertext to `ct_path`.
pub fn encaps(alg: Algorithm, pk_path: &Path, ct_path: &Path) -> Result<String> {
    let pk = read_hex(pk_path)?;
    let mut rng = rand::rng();
    let (ct, ss) = alg.encapsulate(&pk, &mut rng)?;
    write_hex(ct_path, &ct)?;
    Ok(format!(
        "ciphertext     {} ({} bytes)\nshared secret  {}\n",
        ct_path.display(),
        ct.len(),
        ss.to_hex()
    ))
}

/// Decapsulate the ciphertext in `ct_path` with the key in `sk_path`.
pub fn decaps(alg: Algorithm, sk_path: &Path, ct_path: &Path) -> Result<String> {
    let sk = read_hex(sk_path)?;
    let ct = read_hex(ct_path)?;
    let ss = alg.decapsulate(&sk, &ct)?;
    Ok(format!("shared secret  {}\n", ss.to_hex()))
}
