//! `apksigner` — generate, store, and use Android signing keys safely.
//!
//! See the crate README for usage. The binary exposes a CLI (default) and, when
//! built with the `mcp` feature, an MCP server that an AI agent can drive to sign
//! APKs without ever receiving the raw keystore password.

mod backend;
mod cli;
mod commands;
mod config;
mod error;
mod keygen;
mod secret;
mod signer;
mod util;

#[cfg(feature = "mcp")]
mod mcp;

use std::process::ExitCode;

use clap::Parser;

use crate::cli::Cli;

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing(cli.verbose);
    let result = commands::run(cli);
    error::report_exit(result)
}

/// Initialize tracing based on `-v` flags and the `RUST_LOG` env var.
fn init_tracing(verbose: u8) {
    let default = match verbose {
        0 => "warn",
        1 => "info",
        _ => "debug",
    };
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| default.to_string());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}
