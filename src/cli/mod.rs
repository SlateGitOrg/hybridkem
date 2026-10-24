//! Command-line interface definition and dispatch.

mod demo;
mod keys;
pub mod logger;
mod reports;

use clap::{Parser, Subcommand};
use hybridkem::dudect::Target;
use hybridkem::kem::Algorithm;
use hybridkem::noise::Pattern;
use hybridkem::Result;
use std::path::PathBuf;

/// Educational ML-KEM / hybrid KEM / post-quantum Noise toolkit. Not audited.
#[derive(Debug, Parser)]
#[command(name = "hybridkem", version, about, long_about = None)]
pub struct Cli {
    /// Increase log verbosity (-v info, -vv debug).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a key pair, writing <prefix>.sk and <prefix>.pk as hex.
    Keygen {
        /// Algorithm (mlkem512, mlkem768, mlkem1024, x25519, xwing, x25519-mlkem512/768/1024).
        #[arg(long, default_value = "xwing")]
        alg: Algorithm,
        /// Output path prefix.
        #[arg(long)]
        out: PathBuf,
    },
    /// Encapsulate to a public key; writes the ciphertext and prints the shared secret.
    Encaps {
        #[arg(long, default_value = "xwing")]
        alg: Algorithm,
        /// Hex public-key file.
        #[arg(long)]
        pk: PathBuf,
        /// Where to write the hex ciphertext.
        #[arg(long)]
        ct_out: PathBuf,
    },
    /// Decapsulate a ciphertext and print the shared secret.
    Decaps {
        #[arg(long, default_value = "xwing")]
        alg: Algorithm,
        /// Hex secret-key file.
        #[arg(long)]
        sk: PathBuf,
        /// Hex ciphertext file.
        #[arg(long)]
        ct: PathBuf,
    },
    /// Verify vector checksums and run all known-answer tests.
    Kat {
        /// Directory containing SHA256SUMS, acvp/ and xwing/.
        #[arg(long, default_value = "vectors")]
        vectors: PathBuf,
    },
    /// Print median timings for every algorithm and several handshakes.
    Bench {
        /// Iterations per operation.
        #[arg(long, default_value_t = 1000)]
        iters: usize,
    },
    /// Run the dudect-style timing-leak tests (build with --release for meaningful numbers).
    CtTest {
        /// Measurements per target.
        #[arg(long, default_value_t = 20000)]
        samples: usize,
        /// Only run targets whose id contains this string.
        #[arg(long)]
        filter: Option<String>,
        /// Seed for input generation and class interleaving.
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
    /// Run one handshake between two threads over TCP loopback.
    Handshake {
        #[arg(long, default_value = "xwing")]
        alg: Algorithm,
        /// nk, ik or xx.
        #[arg(long, default_value = "ik")]
        pattern: Pattern,
        #[arg(long, default_value_t = 2026)]
        seed: u64,
    },
    /// Offline end-to-end demo of every layer.
    Demo {
        #[arg(long, default_value = "vectors")]
        vectors: PathBuf,
        #[arg(long, default_value_t = 2026)]
        seed: u64,
    },
}

/// Execute a parsed command, returning the text to print and whether it succeeded.
pub fn run(cli: Cli) -> Result<(String, bool)> {
    match cli.command {
        Command::Keygen { alg, out } => Ok((keys::keygen(alg, &out)?, true)),
        Command::Encaps { alg, pk, ct_out } => Ok((keys::encaps(alg, &pk, &ct_out)?, true)),
        Command::Decaps { alg, sk, ct } => Ok((keys::decaps(alg, &sk, &ct)?, true)),
        Command::Kat { vectors } => reports::kat(&vectors),
        Command::Bench { iters } => Ok((reports::bench(iters.max(1)), true)),
        Command::CtTest {
            samples,
            filter,
            seed,
        } => {
            let targets: Vec<Target> = Target::ALL
                .into_iter()
                .filter(|t| filter.as_deref().is_none_or(|f| t.id().contains(f)))
                .collect();
            if targets.is_empty() {
                return Err(hybridkem::Error::Parse(
                    "no dudect target matches the filter".into(),
                ));
            }
            if cfg!(debug_assertions) {
                log::warn!("debug build: timings are not representative; use --release");
            }
            Ok(reports::ct_test(&targets, samples.max(10), seed))
        }
        Command::Handshake { alg, pattern, seed } => {
            Ok((demo::handshake(alg, pattern, seed)?, true))
        }
        Command::Demo { vectors, seed } => {
            // The demo provokes handshake failures on purpose; keep their warnings out of
            // the output unless the user asked for logs.
            if cli.verbose == 0 {
                log::set_max_level(log::LevelFilter::Error);
            }
            Ok((demo::demo(&vectors, seed)?, true))
        }
    }
}
