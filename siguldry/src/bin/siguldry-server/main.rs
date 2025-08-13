// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{path::PathBuf, time::Duration};

use anyhow::Context;
use clap::Parser;
use siguldry::{
    config::load_config,
    server::{service::Server, Config},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    signal::unix::{signal, SignalKind},
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument;
use tracing_subscriber::{fmt::format::FmtSpan, layer::SubscriberExt, EnvFilter};

use crate::management::PromptPassword;

mod acquire_pin;
mod cli;
mod management;

// The path, relative to $XDG_CONFIG_HOME, of the default config file location.
const DEFAULT_CONFIG: &str = "siguldry/server.toml";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = cli::Cli::parse();

    // For management commands the defaults are too noisy.
    let log_filter = if matches!(opts.command, cli::Command::Manage(_))
        && opts.log_filter == "WARN,siguldry=INFO"
    {
        EnvFilter::builder()
            .parse("WARN")
            .context("The developer messed up and provided an invalid default")
    } else {
        // Unfortunately we can't use clap's value_parser since EnvFilter does not
        // implement Clone.
        EnvFilter::builder().parse(&opts.log_filter).context(
            "SIGULDRY_SERVER_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
        )
    }?;

    let stderr_layer = tracing_subscriber::fmt::layer()
        .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
        .with_writer(std::io::stderr);
    let registry = tracing_subscriber::registry()
        .with(stderr_layer)
        .with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    let mut config = load_config::<Config>(opts.config, PathBuf::from(DEFAULT_CONFIG).as_path())?;

    match opts.command {
        cli::Command::Listen {
            credentials_directory,
        } => {
            if !config.pkcs11_bindings.is_empty() {
                acquire_pin::read(&mut config).await?;
            }
            tokio::time::sleep(Duration::from_secs(3)).await;
            config
                .credentials
                .with_credentials_dir(&credentials_directory)?;

            let root_span = tracing::info_span!("server");
            async move {
                let server = Server::new(config).await?;
                let server = server.run();
                tokio::spawn(signal_handler(server.halt_token()));

                server.wait_to_finish().await?;
                Ok::<_, anyhow::Error>(())
            }
            .instrument(root_span)
            .await?;
        }
        cli::Command::EnterPin { socket } => {
            let mut connection =
                timeout(Duration::from_secs(3), UnixStream::connect(socket)).await??;
            let mut buf = String::new();
            timeout(Duration::from_secs(3), connection.read_to_string(&mut buf)).await??;
            let prompt = PromptPassword::new(format!("Please enter the PIN for {buf}:"))?;
            let password = prompt.prompt()?;
            connection.write_all(&password.map(|p| p.to_vec())).await?;
        }
        cli::Command::Config {
            credentials_directory,
        } => {
            println!("# This is the current configuration\n\n{config}\n# This concludes the configuration.\n");
            _ = config.credentials.with_credentials_dir(&credentials_directory).inspect_err(|error|{
                eprintln!("The configuration format is valid, but the referenced credentials aren't valid: {error:?}");
            });
        }
        cli::Command::Manage(command) => management::manage(command, config).await?,
    };

    Ok(())
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
