mod acme;
mod cli;
mod config;
mod crypto;
mod dns;
mod storage;

use anyhow::Result;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    crypto::init_tls();
    let args = cli::Args::parse_from(cli::compatible_argv());
    if args.command.is_none() {
        cli::print_help();
        return Ok(());
    }
    cli::run(args).await
}
