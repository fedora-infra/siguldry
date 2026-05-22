// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

/// Automatically sign content when triggered via AMQP messages.
///
/// The primary feature of this tool is the 'consume' subcommand, which connects to an AMQP broker
/// and signs content when messages arrive.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// The path to the configuration file.
    ///
    /// If no path is provided, the configuration file at $CONFIGURATION_DIRECTORY/fedora-autopen.toml
    /// is used, if it exists. If it does not exist, the configuration defaults are used.
    #[arg(long, short, env = "SIGULDRY_FEDORA_AUTOPEN_CONFIG")]
    pub config: Option<PathBuf>,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(
        long,
        env = "SIGULDRY_FEDORA_AUTOPEN_LOG",
        default_value = "ERROR,lapin=INFO,siguldry_fedora_autopen=INFO,siguldry=INFO"
    )]
    pub log_filter: String,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Consume messages from an AMQP broker
    Consume,

    /// Process a JSON message
    Process { file: PathBuf },
}
