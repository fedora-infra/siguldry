// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

//! This is a helper binary that is run per-connection and is the process that performs the
//! actual signing.
//!
//! Requests are sent over stdin as JSON separated by newlines.
//! Responses are sent over stdout as JSON separated by newlines.

use anyhow::Context;
use clap::Parser;
use siguldry::server::ipc;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

/// Helper binary for the Siguldry server; this is not intended to be called directly.
///
/// This binary is designed to be run via systemd socket activation (siguldry-signer.socket).
/// It reads requests from stdin and writes responses to stdout. The wire format is subject
/// to change at any time and this should be considered a private interface.
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(long, env = "SIGULDRY_SIGNER_LOG", default_value = "INFO")]
    pub log_filter: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_SIGNER_LOG contains an invalid log directive; refer to \
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

    ipc::serve().await
}
