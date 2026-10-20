//! `ldapm` command-line interface. Handlers parse arguments, call
//! `ldapm-core` and print; no directory logic lives here.

mod cli;
mod cmd;
mod ctx;
mod output;

use std::process::ExitCode;

use clap::Parser;
use ldapm_core::error::ErrorKind;

use crate::cli::{Cli, Cmd};
use crate::ctx::Ctx;

/// Exit codes, documented in README.md.
pub mod exit {
    pub const USAGE: u8 = 1;
    pub const DIRECTORY: u8 = 2;
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            let _ = e.print();
            // clap uses 2 for usage errors; ours is 1 (2 means directory error).
            return if e.use_stderr() { ExitCode::from(exit::USAGE) } else { ExitCode::SUCCESS };
        }
    };
    init_tracing(cli.verbose);
    let json = cli.json;

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: cannot start runtime: {e}");
            return ExitCode::from(exit::USAGE);
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let code = match e.kind() {
                ErrorKind::Usage => exit::USAGE,
                ErrorKind::Directory => exit::DIRECTORY,
            };
            if json {
                let err = serde_json::json!({ "error": {
                    "code": e.code(),
                    "message": e.to_string(),
                    "ldap_code": e.ldap_code(),
                    "exit_code": code,
                }});
                eprintln!("{err}");
            } else {
                eprintln!("error: {e}");
            }
            ExitCode::from(code)
        }
    }
}

async fn run(cli: Cli) -> ldapm_core::Result<()> {
    let ctx = Ctx::new(&cli)?;
    match cli.cmd {
        Cmd::Whoami => cmd::whoami::run(&ctx).await,
        Cmd::Profile(c) => cmd::profile::run(&ctx, c).await,
        Cmd::Entry(c) => cmd::entry::run(&ctx, c).await,
        Cmd::User(c) => cmd::user::run(&ctx, c).await,
        Cmd::Group(c) => cmd::group::run(&ctx, c).await,
    }
}

/// `-v` enables our debug logs, `-vv` adds ldap3 debug output. ldap3's
/// `trace` level is always capped: raw protocol messages would include the
/// bind password.
fn init_tracing(verbose: u8) {
    use tracing_subscriber::EnvFilter;
    let base = match verbose {
        0 => std::env::var("RUST_LOG").unwrap_or_else(|_| "warn".into()),
        1 => "warn,ldapm=debug,ldapm_core=debug,ldapm::tunnel=debug".into(),
        _ => "info,ldapm=trace,ldapm_core=trace,ldap3=debug".into(),
    };
    let directives = format!("{base},ldap3=debug,ldap3::conn=debug");
    let filter = EnvFilter::try_new(directives).unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt().with_env_filter(filter).with_writer(std::io::stderr).try_init();
}
