// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;
use siguldry::{
    client::{Client, Config, proxy},
    config::load_config,
    signal_handler,
};
use tokio::net::UnixListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

// The path, relative to $XDG_CONFIG_HOME, of the default config file location.
const DEFAULT_CONFIG: &str = "siguldry/client.toml";

/// The siguldry client
#[derive(Debug, Parser)]
#[command(version)]
struct Cli {
    /// The path to the client's configuration file.
    ///
    /// If no path is provided, the configuration file at $XDG_CONFIG_HOME/siguldry/client.toml
    /// is used, if it exists. If it does not exist, the configuration defaults are used. Note
    /// that the defaults include server hostnames and are useful only as an example.
    ///
    /// To view the client configuration, run the `config` subcommand.
    #[arg(long, short, env = "SIGULDRY_CLIENT_CONFIG")]
    config: Option<PathBuf>,

    /// The directory containing the client's authentication secrets.
    ///
    /// Any file referenced in the configuration that are not absolute paths are
    /// expected to be in this directory. If this value is not supplied and any
    /// configuration values are relative paths, the client will exit with an error.
    ///
    /// The recommended approach to securely store your credentials is with systemd-creds.
    ///
    /// # Example
    ///
    /// ```bash
    /// # Requires systemd v258
    ///
    /// # Encrypt the necessary credentials
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.client.private_key.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.client.private_key.pem"
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.client.certificate.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.client.certificate.pem"
    /// $ systemd-creds encrypt /secure/ramfs/siguldry.ca_certificate.pem \
    ///     "$HOME/.config/credstore.encrypted/siguldry.ca_certificate.pem"
    ///
    /// # Spawn a shell where systemd decrypts the credentials for you.
    /// $ systemd-run --user -S -p "ImportCredentials=siguldry.*"
    /// $ siguldry-client whoami
    /// ```
    #[arg(long, env = "CREDENTIALS_DIRECTORY", verbatim_doc_comment)]
    credentials_directory: Option<PathBuf>,

    /// A set of one or more comma-separated directives to filter logs.
    ///
    /// The general format is "target_name[span_name{field=value}]=level" where level is
    /// one of TRACE, DEBUG, INFO, WARN, ERROR.
    ///
    /// Details: https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/filter/struct.EnvFilter.html#directives
    #[arg(
        long,
        env = "SIGULDRY_CLIENT_LOG",
        default_value = "WARN,siguldry=INFO"
    )]
    pub log_filter: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Attempt to authenticate with the server and print the username of the authenticated user.
    Whoami,
    /// List the users on the server.
    ListUsers,
    /// See the current configuration, or the defaults if no configuration file is supplied.
    Config,
    /// Proxy commands from a local process to the server.
    ///
    /// By default, commands and responses are sent over stdin and stdout respectively.
    Proxy {
        /// If provided, bind a Unix socket to the given location and proxy clients
        /// that connect to it rather than using stdin/stdout.
        ///
        /// NOTE: Any user that has permission to read/write to this socket is able to
        /// connect to the Siguldry server and, if keys are configured to be unlocked,
        /// sign with those keys. Be *VERY* careful about the socket permissions.
        #[arg(long)]
        socket: Option<PathBuf>,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_CLIENT_LOG contains an invalid log directive; refer to \
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

    let mut config = load_config::<Config>(opts.config, PathBuf::from(DEFAULT_CONFIG).as_path())?;

    if let Command::Config = opts.command {
        println!(
            "# This is the current configuration\n\n{config}\n# This concludes the configuration.\n"
        );

        opts.credentials_directory
        .as_ref()
        .map(|path| config.credentials.with_credentials_dir(path).inspect_err(|error|{
            eprintln!("The configuration format is valid, but the referenced credentials aren't valid: {error:?}");
        }));
        return Ok(());
    }

    opts.credentials_directory
        .as_ref()
        .map(|path| config.credentials.with_credentials_dir(path));
    let client = Client::new(config.clone())?;
    match opts.command {
        Command::Whoami => {
            let user = client.who_am_i().await?;
            println!("Hello, {user}, you can successfully authenticate with the server!");
        }
        Command::ListUsers => {
            let users = client.list_users().await?;
            let users = users.join("\n");
            println!("{users}");
        }
        Command::Config => unreachable!("Command handled prior to this match"),
        Command::Proxy { socket } => {
            if let Some(socket) = socket {
                let listener = UnixListener::bind(&socket)
                    .with_context(|| format!("Failed to bind to {}", &socket.display()))?;
                let request_tracker = TaskTracker::new();
                loop {
                    let stream = tokio::select! {
                        _ = halt_token.cancelled() => {
                            tracing::info!("proxy halted; shutting down");
                            return Ok(());
                        }
                        result = listener.accept() => {
                            match result {
                                Ok((unix_stream, _)) => {
                                    unix_stream
                                },
                                Err(error) => {
                                    tracing::error!(?socket, ?error, "Failed to accept request");
                                    break;
                                },
                            }
                        }
                    };
                    let (reader, writer) = tokio::io::split(stream);
                    request_tracker.spawn(
                        proxy(
                            Client::new(config.clone())?,
                            halt_token.clone(),
                            reader,
                            writer,
                        )
                        .instrument(tracing::info_span!("proxy")),
                    );
                }
                request_tracker.close();
                request_tracker.wait().await;
            } else {
                let requests = tokio::io::stdin();
                let responses = tokio::io::stdout();
                proxy(client, halt_token.clone(), requests, responses).await?;
            }
        }
    }

    Ok(())
}
