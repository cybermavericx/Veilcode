//! Veilcode command-line interface (binary `veilcode`).
//!
//! Exit codes (D82): 0 ok, 2 on any error. clap's usage errors are 2 too.
#![forbid(unsafe_code)]

mod args;
mod commands;
mod output;
mod passphrase;

use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let cli = args::Cli::parse();
    match commands::run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Core errors carry paths, ids and counts only, never values.
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}
