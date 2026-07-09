// SPDX-License-Identifier: MIT
// Copyright (c) Microsoft Corporation.

use std::{path::PathBuf, time::Duration};

use anyhow::Context;
use clap::Parser;
use siguldry::{
    client::{Client, Config},
    config::load_config,
    signal_handler,
};
use tokio::net::UnixListener;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::Instrument;
use tracing_subscriber::{EnvFilter, fmt::format::FmtSpan, layer::SubscriberExt};

// The path, relative to $CONFIGURATION_DIRECTORY, of the default config file location.
const DEFAULT_CONFIG: &str = "client.toml";

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

    /// Emit logs when new tracing spans are created, and when they are closed.
    ///
    /// This is useful in debugging scenarios to trace functions and tasks, but can lead to rather
    /// verbose logs.
    #[arg(long)]
    pub span_events: bool,

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
        default_value = "ERROR,siguldry=WARN"
    )]
    pub log_filter: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Attempt to authenticate with the server and print the username of the authenticated user.
    Whoami,
    /// See the current configuration, or the defaults if no configuration file is supplied.
    Config,
    /// Proxy commands from a local process to the server.
    ///
    /// The mode has security implications. Running with `accept-yes` ensures clients are isolated
    /// from one another since each connection runs as its own systemd instance. Running with
    /// `accept-no` does not isolate clients, but does sandbox the proxy which is okay if the proxy
    /// unlocks the signing keys.
    ///
    /// `bind` should only be used for testing purposes as there is no isolation from the host system.
    Proxy {
        /// Control how the proxy accepts requests from clients.
        #[arg(long, value_enum, default_value_t = ProxyMode::AcceptYes)]
        mode: ProxyMode,

        /// If provided, bind a Unix socket to the given location and proxy clients
        /// that connect to it rather than using stdin/stdout.
        ///
        /// NOTE: Any user that has permission to read/write to this socket is able to
        /// connect to the Siguldry server and, if keys are configured to be unlocked,
        /// sign with those keys. Be *VERY* careful about the socket permissions.
        #[arg(long, required_if_eq("mode", "bind"))]
        socket: Option<PathBuf>,
    },
    /// See available keys and certificates.
    #[command(subcommand)]
    Key(KeyCommands),
}

#[derive(Clone, Debug, clap::ValueEnum)]
enum ProxyMode {
    /// Bind a Unix socket to the provided path and accept connections to it
    ///
    /// In this mode, there's no integration or dependency on systemd. This is primarily useful
    /// for test environments and should not be used in production.
    Bind,

    /// Operate in a mode compatible with a systemd socket with the `Accept=yes` configuration
    ///
    /// In this mode, systemd accepts the connection and spawns a new unit instance for it; requests
    /// are accepted over stdin and responses sent over stdout.
    ///
    /// In this mode, every request is isolated in its own process and sytemd sandbox. It's best used
    /// when the client provides the secret to unlock the signing key, and when the request volume is
    /// relatively low and maximum isolation between clients is desirable.
    AcceptYes,

    /// Operate in a mode compatible with a systemd socket with the `Accept=no` configuration
    ///
    /// In this mode, systemd binds the socket and passes the file descriptors on to us. A single
    /// service is run to handle the requests. Different connections to the socket are handled by the
    /// same process, so there is less isolation.
    ///
    /// Each connection still has its own client so keys unlocked by the client are not shared,
    /// but there is no process isolation or separation via namespaces. This mode is best used
    /// when the keys are configured to be unlocked by the proxy rather than by the user of the
    /// socket since there are no user-provided secrets to isolate from each other.
    AcceptNo,
}

#[derive(clap::Subcommand, Debug)]
enum KeyCommands {
    /// List all keys the current user has access to.
    List,
    /// Get a certificate associated with the key by name.
    Cert {
        key: String,
        certificate_name: String,
    },
    /// Get information about a key by name.
    Get {
        /// The name of the key to fetch details for (see available keys with the 'list' command)
        key: String,
        /// If provided, OpenPGP and X509 certificates associated with the key are also shown
        #[arg(long, short, default_value_t)]
        certificates: bool,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Cli::parse();

    // Unfortunately we can't use clap's value_parser since EnvFilter does not
    // implement Clone.
    let log_filter = EnvFilter::builder().parse(&opts.log_filter).context(
        "SIGULDRY_CLIENT_LOG contains an invalid log directive; refer to \
            https://docs.rs/tracing-subscriber/0.3.19/tracing_subscriber/\
            filter/struct.EnvFilter.html#directives for format details.",
    )?;
    let registry = tracing_subscriber::registry();
    let stderr_layer = tracing_subscriber::fmt::layer()
        .without_time()
        .with_writer(std::io::stderr);
    let registry = if opts.span_events {
        registry.with(stderr_layer.with_span_events(FmtSpan::NEW | FmtSpan::CLOSE))
    } else {
        registry.with(stderr_layer)
    };
    let registry = registry.with(log_filter);
    tracing::subscriber::set_global_default(registry)
        .expect("Programming error: set_global_default should only be called once.");

    siguldry::raise_nofiles()?;

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
        Command::Config => unreachable!("Command handled prior to this match"),
        Command::Key(subcommand) => match subcommand {
            KeyCommands::List => {
                let keys = client
                    .list_keys()
                    .await
                    .context("Failed to retrieve key list")?;
                for key in keys {
                    println!("Key: {}", key.name);
                }
            }
            KeyCommands::Cert {
                key,
                certificate_name,
            } => {
                let key = client
                    .get_key(key)
                    .await
                    .context("Failed to fetch key details from the server")?;
                if let Some(cert) = key.certificates.iter().find(|c| c.name == certificate_name) {
                    println!(
                        "{:?} certificate (fingerprint {}):\n{}",
                        cert.certificate_type, cert.fingerprint, cert.certificate
                    );
                } else {
                    eprintln!(
                        "No certificate named '{certificate_name}' is associated with that key"
                    );
                }
            }
            KeyCommands::Get { key, certificates } => {
                let key = client
                    .get_key(key)
                    .await
                    .context("Failed to fetch key details from the server")?;
                println!("Name: {}\nAlgorithm: {}", key.name, key.key_algorithm);
                if certificates {
                    for x509_cert in key.x509_certificates() {
                        println!(
                            "X509 Certificate '{}':\n{}\n",
                            x509_cert.name, x509_cert.certificate
                        );
                    }
                    for pgp_cert in key.openpgp_certificates() {
                        println!(
                            "OpenPGP Certificate '{}':\n{}\n",
                            pgp_cert.name, pgp_cert.certificate
                        );
                    }
                }
            }
        },
        Command::Proxy { mode, socket } => {
            run_proxy(config, client, mode, socket).await?;
        }
    }

    Ok(())
}

async fn run_proxy(
    config: Config,
    client: Client,
    mode: ProxyMode,
    socket: Option<PathBuf>,
) -> anyhow::Result<()> {
    let halt_token = CancellationToken::new();
    tokio::spawn(signal_handler(halt_token.clone()));

    let listener = match mode {
        ProxyMode::Bind => {
            let socket =
                socket.expect("Clap is configured to require this argument when bind mode is set");
            let listener = UnixListener::bind(&socket)
                .with_context(|| format!("Failed to bind to {}", socket.display()))?;
            Some(listener)
        }
        ProxyMode::AcceptYes => None,
        ProxyMode::AcceptNo => {
            let fds = siguldry::listen_fds()
                .context("Environment variables are set, but use invalid values")?;
            if fds.len() > 1 {
                return Err(anyhow::anyhow!(
                    "An unexpected number of file descriptors ({}) were provided",
                    fds.len()
                ));
            }
            let (fd_name, fd) = if let Some(value) = fds.into_iter().next() {
                value
            } else {
                return Err(anyhow::anyhow!(
                    "No file descriptors were provided; this must be run by a systemd socket with Accept=no"
                ));
            };

            let std_listener = std::os::unix::net::UnixListener::from(fd);
            std_listener
                .set_nonblocking(true)
                .context("Failed to set systemd socket to non-blocking mode")?;
            let listener = UnixListener::from_std(std_listener)
                .with_context(|| format!("Failed to create async listener from fd {fd_name:?}"))?;
            tracing::info!(?fd_name, "Listening on systemd-provided socket");
            Some(listener)
        }
    };

    if let Some(listener) = listener {
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(config.proxy_concurrency));
        let request_tracker = TaskTracker::new();
        let mut client = client;
        loop {
            // Once we hit our limit, connections should stack up until they hit the `somaxconn`
            // limit, at which point clients will start getting a connection refused error.
            let permit = tokio::select! {
                _ = halt_token.cancelled() => {
                    break;
                }
                result = semaphore.clone().acquire_owned() => {
                    result
                }
            }?;

            let stream = tokio::select! {
                _ = halt_token.cancelled() => {
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((unix_stream, _)) => {
                            unix_stream
                        },
                        Err(error) => {
                            // We should be really careful here since if we break, we'll wait for existing
                            // connections to complete and never accept new connections, and if we exit immediately
                            // existing connections will fail. To start with, we can log errors loudly and if cases
                            // emerge we really have to exit for, we can add them here.
                            match error.kind() {
                                std::io::ErrorKind::ConnectionAborted => {
                                    tracing::debug!(?error, "Client connection was aborted");
                                },
                                _ => {
                                    match error.raw_os_error() {
                                        Some(libc::EMFILE | libc::ENFILE | libc::ENOMEM | libc::ENOBUFS) => {
                                            tracing::warn!(?error, "Not enough system resources to open another connection - delaying before trying again!");
                                            tokio::select! {
                                                _ = halt_token.cancelled() => break,
                                                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
                                            }
                                            continue;
                                        },
                                        errno => tracing::error!(?error, errno, "An error occurred while accepting the request"),
                                    }
                                }
                            }
                            continue;
                        },
                    }
                }
            };

            let connection_halt_token = halt_token.clone();
            let (reader, writer) = tokio::io::split(stream);
            request_tracker.spawn(
                async move {
                    let _permit = permit;
                    if let Err(error) =
                        siguldry::client::proxy(client, connection_halt_token, reader, writer).await
                    {
                        tracing::warn!(?error, "Proxy connection did not shut down cleanly");
                    }
                }
                .instrument(tracing::info_span!("proxy")),
            );
            client = Client::new(config.clone())?;
        }

        tracing::debug!("Proxy halted; shutting down");
        request_tracker.close();
        if !request_tracker.is_empty() {
            tracing::info!(
                "Waiting for {} connections to complete",
                request_tracker.len()
            );
        }
        request_tracker.wait().await;
    } else {
        let requests = tokio::io::stdin();
        let responses = tokio::io::stdout();
        siguldry::client::proxy(client, halt_token.clone(), requests, responses).await?;
    }

    Ok(())
}
