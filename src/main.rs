//! `hybridkem` command-line tool. Educational; not audited.

#![forbid(unsafe_code)]

mod cli;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let args = cli::Cli::parse();
    cli::logger::init(args.verbose);
    match cli::run(args) {
        Ok((text, ok)) => {
            print!("{text}");
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}
