// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use anyhow::Context;
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

use sigul_pesign_bridge::{cli, listen};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let opts = cli::Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(opts.log_filter).context(
        "SIGUL_PESIGN_BRIDGE_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
    )?;
    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

    match opts.command {
        cli::Command::Listen {
            runtime_directory,
            credentials_directory,
        } => {
            let mut config = opts.config.unwrap_or_default();
            config.fix_credentials(&credentials_directory)?;
            config.validate()?;
            let context = sigul_pesign_bridge::Context::new(config, runtime_directory)?;

            listen(context, halt_token)?.await?
        }
        cli::Command::Config {
            credentials_directory,
        } => {
            let mut config = opts.config.unwrap_or_default();
            println!("{config}");
            let _ = config.fix_credentials(&credentials_directory);
            let _ = config.validate().inspect_err(|e| eprintln!("The configuration format is correct, but contain options which may be invalid: {e:?}")
            );

            Ok(())
        }
    }
}

/// Install and manage signal handlers for the process.
///
/// # SIGTERM and SIGINT
///
/// Sending SIGTERM or SIGINT to the process will cause it to stop accepting new
/// signing requests. Existing signing requests will be allowed to complete
/// before the process shuts down.
async fn signal_handler(halt_token: CancellationToken) -> Result<(), anyhow::Error> {
    let mut sigterm_stream = signal(SignalKind::terminate()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGTERM signal handler");
    })?;
    let mut sigint_stream = signal(SignalKind::interrupt()).inspect_err(|error| {
        tracing::error!(?error, "Failed to register a SIGINT signal handler");
    })?;

    loop {
        tokio::select! {
            _ = sigterm_stream.recv() => {
                tracing::info!("SIGTERM received, beginning service shutdown");
                halt_token.cancel();
            }
            _ = sigint_stream.recv() => {
                tracing::info!("SIGINT received, beginning service shutdown");
                halt_token.cancel();
            }
        }
    }
}
