//! Drives the `hybridkem` binary end to end.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_hybridkem"));
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd
}

fn run(args: &[&str]) -> Output {
    bin().args(args).output().expect("binary runs")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!("hybridkem-cli-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        Self(p)
    }
    fn path(&self, name: &str) -> String {
        self.0.join(name).to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn shared_secret_line(o: &Output) -> String {
    stdout(o)
        .lines()
        .find(|l| l.starts_with("shared secret"))
        .map(|l| l.split_whitespace().last().unwrap().to_string())
        .expect("shared secret printed")
}

#[test]
fn keygen_encaps_decaps_round_trip_for_every_algorithm() {
    let dir = TempDir::new("kem");
    for alg in [
        "mlkem512",
        "mlkem768",
        "mlkem1024",
        "x25519",
        "xwing",
        "x25519-mlkem1024",
    ] {
        let prefix = dir.path(alg);
        let o = run(&["keygen", "--alg", alg, "--out", &prefix]);
        assert!(
            o.status.success(),
            "{alg}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(stdout(&o).contains("fingerprint"));
        let ct = dir.path(&format!("{alg}.ct"));
        let enc = run(&[
            "encaps",
            "--alg",
            alg,
            "--pk",
            &format!("{prefix}.pk"),
            "--ct-out",
            &ct,
        ]);
        assert!(enc.status.success());
        let dec = run(&[
            "decaps",
            "--alg",
            alg,
            "--sk",
            &format!("{prefix}.sk"),
            "--ct",
            &ct,
        ]);
        assert!(dec.status.success());
        assert_eq!(shared_secret_line(&enc), shared_secret_line(&dec), "{alg}");
    }
}

#[test]
fn errors_exit_with_code_2_and_a_message() {
    let dir = TempDir::new("err");
    let prefix = dir.path("k");
    assert!(run(&["keygen", "--alg", "mlkem512", "--out", &prefix])
        .status
        .success());
    // Using an ML-KEM-512 public key with X-Wing is a length error.
    let o = run(&[
        "encaps",
        "--alg",
        "xwing",
        "--pk",
        &format!("{prefix}.pk"),
        "--ct-out",
        &dir.path("c"),
    ]);
    assert_eq!(o.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&o.stderr).contains("invalid hybrid public key length"));
    std::fs::write(dir.path("bad.hex"), "zz\n").unwrap();
    let o = run(&[
        "decaps",
        "--alg",
        "mlkem512",
        "--sk",
        &dir.path("bad.hex"),
        "--ct",
        &dir.path("bad.hex"),
    ]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["kat", "--vectors", "/nonexistent-dir"]);
    assert_eq!(o.status.code(), Some(2));
    let o = run(&["keygen", "--alg", "rsa2048", "--out", &prefix]);
    assert_eq!(o.status.code(), Some(2), "clap rejects unknown algorithms");
    let o = run(&["ct-test", "--filter", "no-such-target"]);
    assert_eq!(o.status.code(), Some(2));
}

#[test]
fn kat_command_reports_every_vector() {
    let o = run(&["kat"]);
    assert!(o.status.success());
    let out = stdout(&o);
    assert!(out.contains("total: 243/243 vectors passed"), "{out}");
    assert!(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/SHA256SUMS")
        .exists());
}

#[test]
fn handshake_bench_ct_and_demo_commands_run() {
    let o = run(&["handshake", "--alg", "mlkem512", "--pattern", "xx"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("HybridNoise_pqXX_ML-KEM-512_ChaChaPoly_SHA256"));

    let o = run(&["bench", "--iters", "2"]);
    assert!(o.status.success());
    assert!(stdout(&o).contains("| ML-KEM-1024 | 1568 | 1568 |"));

    // Plumbing only: debug-build timings are meaningless, so the verdict is not asserted.
    let o = run(&["-v", "ct-test", "--samples", "50", "--filter", "subtle"]);
    assert_ne!(o.status.code(), Some(2));
    assert!(stdout(&o).contains("subtle-ct-eq-1088B"));

    let o = run(&["demo"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = stdout(&o);
    for needle in [
        "243/243 vectors passed",
        "agree=true",
        "different secrets=true",
        "server echo: second message",
        "replayed transport record      -> rejected",
    ] {
        assert!(out.contains(needle), "missing {needle:?} in demo output");
    }
}
